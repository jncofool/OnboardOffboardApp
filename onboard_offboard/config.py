"""Configuration loading utilities for the onboarding/offboarding toolkit."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import yaml


DEFAULT_CONFIG_PATH = Path("config/settings.yaml")
ENV_CONFIG_PATH = "ONBOARD_CONFIG"
ENV_PREFIX = "ONBOARD_"


@dataclass
class LDAPConfig:
    """Settings required to connect to Active Directory via LDAP."""

    server_uri: str
    user_dn: str
    password: str
    base_dn: str
    user_ou: str
    use_ssl: bool = True
    manager_search_filter: str = "(objectClass=user)"
    manager_attributes: tuple[str, ...] = ("displayName", "mail", "title")
    mock_data_file: Optional[Path] = None


@dataclass
class SyncConfig:
    """Settings for executing a directory sync command (e.g. Azure AD Connect)."""

    command: str
    shell: bool = False
    timeout: int = 120


@dataclass
class StorageConfig:
    """Filesystem locations used by the application."""

    job_roles_file: Path = Path("data/job_roles.yaml")


@dataclass
class AppConfig:
    """Aggregate configuration for the application."""

    ldap: LDAPConfig
    sync: SyncConfig
    storage: StorageConfig = field(default_factory=StorageConfig)


class ConfigurationError(RuntimeError):
    """Raised when the configuration file or environment variables are invalid."""


def _load_from_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise ConfigurationError(
            f"Configuration file '{path}' does not exist. "
            "Create it from 'config/settings.example.yaml' or set environment variables."
        )
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def _apply_environment_overrides(config_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Override configuration values with environment variables."""

    overrides: Dict[str, Any] = {}
    for key, value in os.environ.items():
        if not key.startswith(ENV_PREFIX):
            continue
        path = key[len(ENV_PREFIX) :].lower().split("__")
        node = overrides
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = value

    if overrides:
        config_dict = _deep_merge(config_dict, overrides)
    return config_dict


def _deep_merge(base: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            result[key] = _deep_merge(base[key], value)
        else:
            result[key] = value
    return result


def _load_config_dict(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or Path(os.environ.get(ENV_CONFIG_PATH, DEFAULT_CONFIG_PATH))
    config_dict = _load_from_file(path)
    return _apply_environment_overrides(config_dict)


def _get_required(config_dict: Dict[str, Any], key: str) -> Dict[str, Any]:
    try:
        return config_dict[key]
    except KeyError as exc:
        raise ConfigurationError(f"Missing required configuration section: '{key}'.") from exc


def _normalize_sequence(value: Any) -> Iterable[Any]:
    if isinstance(value, (list, tuple, set)):
        return value
    return [value]


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _to_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value.strip())
    return int(value)


def load_config(path: Optional[Path] = None) -> AppConfig:
    """Load application configuration from disk and environment variables."""

    config_dict = _load_config_dict(path)
    ldap_section = _get_required(config_dict, "ldap")
    sync_section = _get_required(config_dict, "sync")

    try:
        ldap_config = LDAPConfig(
            server_uri=ldap_section["server_uri"],
            user_dn=ldap_section["user_dn"],
            password=str(ldap_section["password"]),
            base_dn=ldap_section["base_dn"],
            user_ou=ldap_section["user_ou"],
            use_ssl=_to_bool(ldap_section.get("use_ssl", True)),
            manager_search_filter=str(
                ldap_section.get("manager_search_filter", "(objectClass=user)")
            ),
            manager_attributes=tuple(
                _normalize_sequence(
                    ldap_section.get("manager_attributes", ("displayName", "mail", "title"))
                )
            ),
            mock_data_file=Path(ldap_section["mock_data_file"]) if "mock_data_file" in ldap_section else None,
        )
    except KeyError as exc:
        raise ConfigurationError(f"Missing LDAP configuration key: {exc}.") from exc

    try:
        sync_config = SyncConfig(
            command=str(sync_section["command"]),
            shell=_to_bool(sync_section.get("shell", False)),
            timeout=_to_int(sync_section.get("timeout", 120)),
        )
    except KeyError as exc:
        raise ConfigurationError(f"Missing sync configuration key: {exc}.") from exc

    storage_section = config_dict.get("storage", {})
    storage_config = StorageConfig(
        job_roles_file=Path(storage_section.get("job_roles_file", StorageConfig().job_roles_file))
    )

    return AppConfig(ldap=ldap_config, sync=sync_config, storage=storage_config)


__all__ = [
    "AppConfig",
    "ConfigurationError",
    "LDAPConfig",
    "SyncConfig",
    "StorageConfig",
    "load_config",
]
