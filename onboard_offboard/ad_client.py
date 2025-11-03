"""Active Directory helper client based on ldap3."""
from __future__ import annotations

import contextlib
import copy
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import yaml
from ldap3 import ALL, BASE, LEVEL, MODIFY_REPLACE, SUBTREE, Connection, Server

from .config import LDAPConfig
from .models import Employee, JobRole


class MockDirectory:
    """Lightweight directory emulator used when ldap3 connectivity isn't available."""

    def __init__(self, data_file: Optional[Path]):
        self.data_file = data_file
        self._data: Dict[str, Any] = {
            "managers": [],
            "tree": {},
            "users": [],
        }
        self._load()

    def _load(self) -> None:
        if self.data_file and self.data_file.exists():
            with self.data_file.open("r", encoding="utf-8") as handle:
                self._data = yaml.safe_load(handle) or self._data
        elif not self._data.get("tree"):
            # Provide a sensible default tree if none supplied.
            self._data["tree"] = {"name": "", "children": []}

    def _save(self) -> None:
        if not self.data_file:
            return
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        with self.data_file.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(self._data, handle, sort_keys=False, indent=2)

    def list_managers(self) -> List[Dict[str, str]]:
        return [dict(manager) for manager in self._data.get("managers", [])]

    def tree_for(self, base_dn: str, depth: int) -> Dict[str, Any]:
        tree = self._data.get("tree") or {"name": base_dn, "children": []}
        subtree = self._find_subtree(tree, base_dn) if base_dn else tree
        if not subtree:
            subtree = {"name": base_dn, "children": []}
        trimmed = self._trim_tree(subtree, depth)
        return trimmed

    def _find_subtree(self, node: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
        if not target or node.get("name") == target:
            return node
        for child in node.get("children", []):
            found = self._find_subtree(child, target)
            if found:
                return found
        return None

    def _trim_tree(self, node: Dict[str, Any], depth: int) -> Dict[str, Any]:
        result = {"name": node.get("name"), "children": []}
        if depth <= 0:
            return result
        if depth == 1:
            return result
        for child in node.get("children", []):
            result["children"].append(self._trim_tree(child, depth - 1))
        return result

    def add_user(self, distinguished_name: str, attributes: Dict[str, Any]) -> None:
        users = self._data.setdefault("users", [])
        existing = next((user for user in users if user.get("distinguished_name") == distinguished_name), None)
        payload = {"distinguished_name": distinguished_name, "attributes": dict(attributes)}
        if existing:
            existing.update(payload)
        else:
            users.append(payload)
        self._save()

    def update_manager(self, user_dn: str, manager_dn: str) -> None:
        for user in self._data.setdefault("users", []):
            if user.get("distinguished_name") == user_dn:
                attrs = user.setdefault("attributes", {})
                attrs["manager"] = manager_dn
                break
        self._save()

    def search_users(self, query: str, attributes: List[str]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        lowered = query.lower()
        for user in self._data.get("users", []):
            attrs = user.get("attributes", {})
            haystack = " ".join(
                str(attrs.get(key, "")) for key in ("displayName", "sAMAccountName", "mail")
            ).lower()
            if lowered in haystack:
                record = {"distinguishedName": user.get("distinguished_name")}
                for attribute in attributes:
                    record[attribute] = attrs.get(attribute)
                results.append(record)
        return results

    def get_user(self, distinguished_name: str, attributes: List[str]) -> Optional[Dict[str, Any]]:
        for user in self._data.get("users", []):
            if user.get("distinguished_name") == distinguished_name:
                record = {"distinguishedName": distinguished_name}
                attrs = user.get("attributes", {})
                for attribute in attributes:
                    record[attribute] = attrs.get(attribute)
                return record
        return None

    def delete_user(self, distinguished_name: str) -> bool:
        users = self._data.get("users", [])
        for index, user in enumerate(users):
            if user.get("distinguished_name") == distinguished_name:
                users.pop(index)
                self._save()
                return True
        return False

class ADClient:
    """Wrapper around ldap3 that exposes high-level AD operations."""

    def __init__(self, config: LDAPConfig):
        self.config = config
        self._mock_directory: Optional[MockDirectory] = None
        self.connection: Optional[Connection] = None

        if config.server_uri.startswith("mock://"):
            data_file = config.mock_data_file
            self._mock_directory = MockDirectory(data_file)
            self.connection = None
        else:
            self.server = Server(config.server_uri, use_ssl=config.use_ssl, get_info=ALL)
            self.connection = Connection(
                self.server,
                user=config.user_dn,
                password=config.password,
                auto_bind=True,
            )

    def close(self) -> None:
        if self.connection and self.connection.bound:
            self.connection.unbind()

    def __enter__(self) -> "ADClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        self.close()

    # Manager helpers -----------------------------------------------------
    def list_potential_managers(
        self, search_base: Optional[str] = None, search_filter: Optional[str] = None
    ) -> List[Dict[str, str]]:
        if self._mock_directory:
            return self._mock_directory.list_managers()

        assert self.connection is not None
        base_dn = search_base or self.config.base_dn
        filter_str = search_filter or self.config.manager_search_filter
        attributes = set(self.config.manager_attributes) | {"distinguishedName"}
        self.connection.search(
            search_base=base_dn,
            search_filter=filter_str,
            search_scope=SUBTREE,
            attributes=list(attributes),
        )
        results: List[Dict[str, str]] = []
        for entry in self.connection.entries:
            payload = {attr: str(entry[attr]) for attr in attributes if attr in entry}
            results.append(payload)
        return results

    # Directory tree ------------------------------------------------------
    def fetch_directory_tree(self, base_dn: Optional[str] = None, depth: int = 2) -> Dict[str, Any]:
        if self._mock_directory:
            return self._mock_directory.tree_for(base_dn or self.config.base_dn, depth)

        assert self.connection is not None
        base_dn = base_dn or self.config.base_dn
        tree: Dict[str, Any] = {"name": base_dn, "children": []}

        def _walk(current_dn: str, current_depth: int) -> List[Dict[str, Any]]:
            if current_depth == 0:
                return []
            self.connection.search(
                search_base=current_dn,
                search_filter="(objectClass=organizationalUnit)",
                search_scope=LEVEL,
                attributes=["ou"],
            )
            children = []
            for entry in self.connection.entries:
                dn = str(entry.entry_dn)
                children.append(
                    {
                        "name": dn,
                        "children": _walk(dn, current_depth - 1),
                    }
                )
            return children

        tree["children"] = _walk(base_dn, depth)
        return tree

    # Provisioning --------------------------------------------------------
    def create_user(
        self,
        employee: Employee,
        job_role: JobRole,
        password: Optional[str],
        enable_account: bool = True,
    ) -> Dict[str, str]:
        user_ou = job_role.user_ou or self.config.user_ou
        distinguished_name = employee.distinguished_name(user_ou, self.config.base_dn)

        attributes = {
            "givenName": employee.first_name,
            "sn": employee.last_name,
            "displayName": employee.display_name,
            "userPrincipalName": f"{employee.username}@{self._domain_from_dn(self.config.base_dn)}",
            "sAMAccountName": employee.username,
            "mail": employee.email,
            **job_role.attributes,
            **employee.attributes,
        }

        if employee.manager_dn:
            attributes["manager"] = employee.manager_dn

        if self._mock_directory:
            record_attributes = copy.deepcopy(attributes)
            record_attributes["userAccountControl"] = 512 if enable_account else 514
            self._mock_directory.add_user(distinguished_name, record_attributes)
        else:
            assert self.connection is not None
            self.connection.add(
                dn=distinguished_name,
                object_class=["top", "person", "organizationalPerson", "user"],
                attributes=attributes,
            )

            if password:
                self.connection.extend.microsoft.modify_password(distinguished_name, password)
            if enable_account:
                # Enable account by setting userAccountControl to 512 (NORMAL_ACCOUNT)
                self.connection.modify(
                    distinguished_name, {"userAccountControl": [(MODIFY_REPLACE, [512])]}
                )

        return {
            "distinguished_name": distinguished_name,
            "sAMAccountName": employee.username,
        }

    def update_manager(self, user_dn: str, manager_dn: str) -> None:
        if self._mock_directory:
            self._mock_directory.update_manager(user_dn, manager_dn)
            return
        assert self.connection is not None
        self.connection.modify(user_dn, {"manager": [(MODIFY_REPLACE, [manager_dn])]})

    # User discovery ------------------------------------------------------
    def search_users(
        self, query: str, attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        if not query:
            return []

        attribute_list = list({"displayName", "mail", "title", "sAMAccountName", *(attributes or [])})

        if self._mock_directory:
            return self._mock_directory.search_users(query, attribute_list)

        assert self.connection is not None
        escaped_query = self._escape_filter_value(query)
        filter_str = (
            f"(&"
            f"(objectClass=user)"
            f"(|(displayName=*{escaped_query}*)(sAMAccountName=*{escaped_query}*)(mail=*{escaped_query}*))"
            f")"
        )
        self.connection.search(
            search_base=self.config.base_dn,
            search_filter=filter_str,
            search_scope=SUBTREE,
            attributes=attribute_list,
        )

        results: List[Dict[str, Any]] = []
        for entry in self.connection.entries:
            payload = {"distinguishedName": str(entry.entry_dn)}
            for attribute in attribute_list:
                if attribute in entry:
                    payload[attribute] = str(entry[attribute])
            results.append(payload)
        return results

    def get_user(
        self, distinguished_name: str, attributes: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        attribute_list = list({"displayName", "mail", "title", "manager", *(attributes or [])})

        if self._mock_directory:
            return self._mock_directory.get_user(distinguished_name, attribute_list)

        assert self.connection is not None
        self.connection.search(
            search_base=distinguished_name,
            search_filter="(objectClass=user)",
            search_scope=BASE,
            attributes=attribute_list,
        )
        if not self.connection.entries:
            return None
        entry = self.connection.entries[0]
        payload = {"distinguishedName": str(entry.entry_dn)}
        for attribute in attribute_list:
            if attribute in entry:
                payload[attribute] = str(entry[attribute])
        return payload

    def delete_user(self, distinguished_name: str) -> bool:
        if self._mock_directory:
            return self._mock_directory.delete_user(distinguished_name)

        assert self.connection is not None
        return bool(self.connection.delete(distinguished_name))
    # Utilities -----------------------------------------------------------
    @staticmethod
    def _domain_from_dn(base_dn: str) -> str:
        parts = [segment.split("=")[1] for segment in base_dn.split(",") if segment.upper().startswith("DC=")]
        return ".".join(parts)
    @staticmethod
    def _escape_filter_value(value: str) -> str:
        replacements = {
            "\\": r"\\5c",
            "*": r"\\2a",
            "(": r"\\28",
            ")": r"\\29",
            "\0": r"\\00",
        }
        return "".join(replacements.get(char, char) for char in value)

@contextlib.contextmanager
def ad_client(config: LDAPConfig) -> Iterator[ADClient]:
    client = ADClient(config)
    try:
        yield client
    finally:
        client.close()


__all__ = ["ADClient", "ad_client"]
