"""Active Directory helper client based on ldap3."""
from __future__ import annotations

import contextlib
import copy
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

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
            "groups": [],
        }
        self._load()

    def _load(self) -> None:
        if self.data_file and self.data_file.exists():
            with self.data_file.open("r", encoding="utf-8") as handle:
                self._data = yaml.safe_load(handle) or self._data
        elif not self._data.get("tree"):
            # Provide a sensible default tree if none supplied.
            self._data["tree"] = {"name": "", "children": []}
        self._data.setdefault("managers", [])
        self._data.setdefault("tree", {"name": "", "children": []})
        self._data.setdefault("users", [])
        self._data.setdefault("groups", [])

    def _save(self) -> None:
        if not self.data_file:
            return
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        with self.data_file.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(self._data, handle, sort_keys=False, indent=2)

    def list_managers(self) -> List[Dict[str, str]]:
        return [dict(manager) for manager in self._data.get("managers", [])]

    def list_groups(self, query: Optional[str] = None, limit: int = 25) -> List[Dict[str, str]]:
        groups: List[Dict[str, str]] = []
        lowered_query = query.lower() if query else None
        for group in self._data.get("groups", []):
            name = str(group.get("name") or "")
            dn = str(group.get("distinguished_name") or "")
            if lowered_query and lowered_query not in f"{name} {dn}".lower():
                continue
            groups.append(
                {
                    "name": name,
                    "distinguishedName": dn,
                    "description": group.get("description"),
                }
            )
            if len(groups) >= limit:
                break
        return groups

    def list_job_titles(self, query: Optional[str] = None, limit: int = 25) -> List[str]:
        titles: List[str] = []
        for user in self._data.get("users", []):
            title = user.get("attributes", {}).get("title")
            if not title:
                continue
            titles.append(str(title))
        unique_titles = []
        seen = set()
        lowered_query = query.lower() if query else None
        for title in titles:
            if lowered_query and lowered_query not in title.lower():
                continue
            if title not in seen:
                seen.add(title)
                unique_titles.append(title)
        unique_titles.sort()
        return unique_titles[:limit]

    def list_companies(self, query: Optional[str] = None, limit: int = 25) -> List[str]:
        lowered_query = query.lower() if query else None
        seen: set[str] = set()
        companies: List[str] = []
        for user in self._data.get("users", []):
            company = user.get("attributes", {}).get("company")
            if not company:
                continue
            company = str(company)
            if lowered_query and lowered_query not in company.lower():
                continue
            if company not in seen:
                seen.add(company)
                companies.append(company)
        companies.sort()
        return companies[:limit]

    def list_offices(self, query: Optional[str] = None, limit: int = 25) -> List[str]:
        lowered_query = query.lower() if query else None
        seen: set[str] = set()
        offices: List[str] = []
        for user in self._data.get("users", []):
            office = user.get("attributes", {}).get("physicalDeliveryOfficeName")
            if not office:
                continue
            office = str(office)
            if lowered_query and lowered_query not in office.lower():
                continue
            if office not in seen:
                seen.add(office)
                offices.append(office)
        offices.sort()
        return offices[:limit]

    def search_managers(self, query: str, limit: int = 25) -> List[Dict[str, str]]:
        lowered = query.lower()
        results: List[Dict[str, str]] = []
        for manager in self.list_managers():
            haystack = " ".join(
                str(manager.get(key, ""))
                for key in ("displayName", "distinguishedName", "mail", "title")
            ).lower()
            if lowered in haystack:
                results.append(dict(manager))
            if len(results) >= limit:
                break
        return results

    def search_organizational_units(self, query: Optional[str] = None, limit: int = 25) -> List[str]:
        tree = self._data.get("tree") or {}
        entries: List[str] = []
        lowered = query.lower() if query else None

        def _walk(node: Dict[str, Any]) -> None:
            name = node.get("name")
            if name and name.upper().startswith("OU="):
                if not lowered or lowered in name.lower():
                    entries.append(name)
            for child in node.get("children", []):
                _walk(child)

        _walk(tree)
        entries = sorted(dict.fromkeys(entries))
        return entries[:limit]

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
        attrs = dict(attributes)
        attrs.setdefault("memberOf", list(attributes.get("memberOf", [])))
        payload = {"distinguished_name": distinguished_name, "attributes": attrs}
        if existing:
            existing.update(payload)
        else:
            users.append(payload)
        self._save()

    def get_user_groups(self, distinguished_name: str) -> List[str]:
        for user in self._data.get("users", []):
            if user.get("distinguished_name") == distinguished_name:
                groups = user.get("attributes", {}).get("memberOf", []) or []
                return [str(value) for value in groups]
        return []

    def add_user_to_groups(self, distinguished_name: str, groups: Iterable[str]) -> None:
        users = self._data.setdefault("users", [])
        target = next((user for user in users if user.get("distinguished_name") == distinguished_name), None)
        if not target:
            return
        attrs = target.setdefault("attributes", {})
        existing = set(str(value) for value in attrs.get("memberOf", []) or [])
        updated = list(existing.union(str(g) for g in groups if g))
        attrs["memberOf"] = updated
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

    def list_job_titles(self, query: Optional[str] = None, limit: int = 25) -> List[str]:
        limit = self._clamp_limit(limit)
        if self._mock_directory:
            return self._mock_directory.list_job_titles(query, limit)

        assert self.connection is not None
        base_dn = self.config.base_dn
        if query:
            escaped = self._escape_filter_value(query)
            filter_str = f"(&(objectClass=user)(title=*{escaped}*))"
        else:
            filter_str = "(&(objectClass=user)(title=*))"

        return self._paged_attribute_values(base_dn, filter_str, "title", limit)

    def list_companies(self, query: Optional[str] = None, limit: int = 25) -> List[str]:
        limit = self._clamp_limit(limit)
        if self._mock_directory:
            return self._mock_directory.list_companies(query, limit)

        assert self.connection is not None
        base_dn = self.config.base_dn
        if query:
            escaped = self._escape_filter_value(query)
            filter_str = f"(&(objectClass=user)(company=*{escaped}*))"
        else:
            filter_str = "(&(objectClass=user)(company=*))"

        return self._paged_attribute_values(base_dn, filter_str, "company", limit)

    def list_groups(self, query: Optional[str] = None, limit: int = 25) -> List[Dict[str, str]]:
        limit = self._clamp_limit(limit)
        if self._mock_directory:
            return self._mock_directory.list_groups(query, limit)

        assert self.connection is not None
        base_dn = self.config.group_search_base or self.config.base_dn
        if query:
            escaped = self._escape_filter_value(query)
            filter_str = (
                f"(&"
                f"(objectClass=group)"
                f"(|(cn=*{escaped}*)(name=*{escaped}*)(sAMAccountName=*{escaped}*))"
                f")"
            )
        else:
            filter_str = "(objectClass=group)"

        self.connection.search(
            search_base=base_dn,
            search_filter=filter_str,
            search_scope=SUBTREE,
            attributes=["cn", "distinguishedName", "sAMAccountName", "description"],
            size_limit=limit,
        )

        groups: List[Dict[str, str]] = []
        seen = set()
        for entry in self.connection.entries:
            dn = str(entry.entry_dn)
            if dn in seen:
                continue
            seen.add(dn)

            def _single_value(attr: str) -> str:
                if attr not in entry:
                    return ""
                value = entry[attr].value
                if isinstance(value, (list, tuple)):
                    return value[0] if value else ""
                return str(value) if value is not None else ""

            groups.append(
                {
                    "name": _single_value("cn") or dn,
                    "distinguishedName": dn,
                    "sAMAccountName": _single_value("sAMAccountName") or None,
                    "description": _single_value("description") or None,
                }
            )
            if len(groups) >= limit:
                break
        return groups

    def list_offices(self, query: Optional[str] = None, limit: int = 25) -> List[str]:
        limit = self._clamp_limit(limit)
        if self._mock_directory:
            return self._mock_directory.list_offices(query, limit)

        assert self.connection is not None
        base_dn = self.config.base_dn
        attribute = "physicalDeliveryOfficeName"
        if query:
            escaped = self._escape_filter_value(query)
            filter_str = f"(&(objectClass=user)({attribute}=*{escaped}*))"
        else:
            filter_str = f"(&(objectClass=user)({attribute}=*))"

        return self._paged_attribute_values(base_dn, filter_str, attribute, limit)

    def _paged_attribute_values(
        self,
        search_base: str,
        search_filter: str,
        attribute: str,
        limit: int,
    ) -> List[str]:
        """Return unique string values for an attribute using a paged LDAP search."""

        assert self.connection is not None

        page_size = min(max(limit, 100), 1000)
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[attribute],
            paged_size=page_size,
            generator=True,
        )

        values: List[str] = []
        seen: set[str] = set()
        for entry in results:
            if entry.get("type") != "searchResEntry":
                continue
            attributes = entry.get("attributes", {})
            raw_value = attributes.get(attribute)
            if not raw_value:
                continue

            if isinstance(raw_value, (list, tuple, set)):
                candidates = raw_value
            else:
                candidates = [raw_value]

            for candidate in candidates:
                normalized = str(candidate).strip()
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                values.append(normalized)
                if len(values) >= limit:
                    return sorted(values, key=str.casefold)

        return sorted(values, key=str.casefold)

    def search_managers(self, query: str, limit: int = 25) -> List[Dict[str, str]]:
        limit = self._clamp_limit(limit)
        if not query:
            return []
        if self._mock_directory:
            return self._mock_directory.search_managers(query, limit)

        assert self.connection is not None
        base_dn = self.config.group_search_base or self.config.base_dn
        filter_str = self.config.manager_search_filter or "(objectClass=user)"
        escaped = self._escape_filter_value(query)
        combined_filter = f"(&{filter_str}(|(displayName=*{escaped}*)(sAMAccountName=*{escaped}*)(mail=*{escaped}*)))"
        attributes = list(
            set(self.config.manager_attributes)
            | {"distinguishedName", "sAMAccountName", "userPrincipalName"}
        )

        self.connection.search(
            search_base=base_dn,
            search_filter=combined_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            size_limit=limit,
        )
        results: List[Dict[str, str]] = []
        for entry in self.connection.entries:
            payload = {}
            for attribute in attributes:
                if attribute in entry:
                    payload[attribute] = str(entry[attribute])
            if payload:
                results.append(payload)
            if len(results) >= limit:
                break
        return results

    def search_organizational_units(self, query: Optional[str] = None, limit: int = 25) -> List[str]:
        limit = self._clamp_limit(limit)
        if self._mock_directory:
            return self._mock_directory.search_organizational_units(query, limit)

        assert self.connection is not None
        base_dn = self.config.group_search_base or self.config.base_dn
        if query:
            escaped = self._escape_filter_value(query)
            filter_str = f"(&(objectClass=organizationalUnit)(ou=*{escaped}*))"
        else:
            filter_str = "(&(objectClass=organizationalUnit)(ou=*))"

        self.connection.search(
            search_base=base_dn,
            search_filter=filter_str,
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
            size_limit=limit,
        )

        ous: List[str] = []
        seen = set()
        for entry in self.connection.entries:
            dn = str(entry.entry_dn)
            if dn not in seen:
                seen.add(dn)
                ous.append(dn)
            if len(ous) >= limit:
                break
        ous.sort()
        return ous

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
            added = self.connection.add(
                dn=distinguished_name,
                object_class=["top", "person", "organizationalPerson", "user"],
                attributes=attributes,
            )
            if not added:
                result = self.connection.result or {}
                description = result.get("description", "Unknown error")
                message = result.get("message")
                raise RuntimeError(
                    f"Active Directory rejected the user creation request ({description})."
                    + (f" {message}" if message else "")
                )

            if password:
                self.connection.extend.microsoft.modify_password(distinguished_name, password)
            if enable_account:
                # Enable account by setting userAccountControl to 512 (NORMAL_ACCOUNT)
                enabled = self.connection.modify(
                    distinguished_name, {"userAccountControl": [(MODIFY_REPLACE, [512])]}
                )
                if not enabled:
                    result = self.connection.result or {}
                    description = result.get("description", "Unknown error")
                    message = result.get("message")
                    raise RuntimeError(
                        f"Active Directory rejected the enable-account request ({description})."
                        + (f" {message}" if message else "")
                    )

        groups = [group for group in dict.fromkeys(employee.groups) if group]
        if groups:
            self.add_user_to_groups(distinguished_name, groups)

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

    def get_user_groups(self, user_dn: str) -> List[str]:
        if self._mock_directory:
            return self._mock_directory.get_user_groups(user_dn)

        assert self.connection is not None
        base_dn = self.config.group_search_base or self.config.base_dn
        escaped_dn = self._escape_filter_value(user_dn)
        search_filter = f"(&(objectClass=group)(member={escaped_dn}))"
        self.connection.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
            paged_size=500,
        )
        groups: List[str] = []
        for entry in self.connection.entries or []:
            groups.append(str(entry.entry_dn))
        return groups

    def add_user_to_groups(self, user_dn: str, groups: Iterable[str]) -> None:
        unique_groups = [group for group in dict.fromkeys(groups) if group]
        if not unique_groups:
            return
        if self._mock_directory:
            self._mock_directory.add_user_to_groups(user_dn, unique_groups)
            return

        assert self.connection is not None
        added = self.connection.extend.microsoft.add_members_to_groups([user_dn], unique_groups)
        if not added:
            result = self.connection.result or {}
            description = result.get("description", "Unknown error")
            message = result.get("message")
            raise RuntimeError(
                f"Unable to assign groups to {user_dn} ({description})."
                + (f" {message}" if message else "")
            )

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
    def _clamp_limit(value: int, maximum: int = 100) -> int:
        try:
            numeric = int(value)
        except (TypeError, ValueError):
            numeric = 25
        return max(1, min(numeric, maximum))

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
