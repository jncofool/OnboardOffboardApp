"""Configuration loading utilities for the onboarding/offboarding toolkit."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import shutil

import yaml


DEFAULT_CONFIG_PATH = Path("config/settings.yaml")
DEFAULT_TEMPLATE_PATH = Path("config/settings.example.yaml")
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


def _resolve_config_path(path: Optional[Path] = None) -> Path:
    if path is not None:
        return Path(path)
    env_path = os.environ.get(ENV_CONFIG_PATH)
    if env_path:
        return Path(env_path)
    return DEFAULT_CONFIG_PATH


def ensure_default_config(
    path: Optional[Path] = None, template_path: Optional[Path] = None
) -> Path:
    """Ensure a configuration file exists, copying from the example if needed."""

    target_path = _resolve_config_path(path)
    if target_path.exists():
        return target_path

    template = Path(template_path) if template_path is not None else DEFAULT_TEMPLATE_PATH
    if not template.exists():
        raise ConfigurationError(
            "Default configuration template not found. "
            "Ensure 'config/settings.example.yaml' is present or specify a template."
        )

    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(template, target_path)
    return target_path


def _load_config_dict(path: Optional[Path] = None) -> Dict[str, Any]:
    resolved_path = _resolve_config_path(path)
    if resolved_path == DEFAULT_CONFIG_PATH:
        ensure_default_config(resolved_path)

    config_dict = _load_from_file(resolved_path)
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


def _optional_path(raw: Any) -> Optional[Path]:
    """Convert a raw config value to ``Path`` if set, otherwise ``None``."""

    if raw is None:
        return None
    if isinstance(raw, Path):
        return raw
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        return Path(stripped)
    return Path(raw)


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
            mock_data_file=_optional_path(ldap_section.get("mock_data_file")),
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


def config_to_dict(config: AppConfig) -> Dict[str, Any]:
    """Serialize an :class:`AppConfig` back to primitive types for persistence."""

    return {
        "ldap": {
            "server_uri": config.ldap.server_uri,
            "user_dn": config.ldap.user_dn,
            "password": config.ldap.password,
            "base_dn": config.ldap.base_dn,
            "user_ou": config.ldap.user_ou,
            "use_ssl": config.ldap.use_ssl,
            "manager_search_filter": config.ldap.manager_search_filter,
            "manager_attributes": list(config.ldap.manager_attributes),
            **(
                {"mock_data_file": str(config.ldap.mock_data_file)}
                if config.ldap.mock_data_file
                else {}
            ),
        },
        "sync": {
            "command": config.sync.command,
            "shell": config.sync.shell,
            "timeout": config.sync.timeout,
        },
        "storage": {
            "job_roles_file": str(config.storage.job_roles_file),
        },
    }


def save_config(config: AppConfig, path: Optional[Path] = None) -> Path:
    """Persist the configuration to disk, returning the path that was written."""

    target = _resolve_config_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = config_to_dict(config)
    with target.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False, indent=2)
    return target


__all__ = [
    "AppConfig",
    "ConfigurationError",
    "config_to_dict",
    "ensure_default_config",
    "LDAPConfig",
    "SyncConfig",
    "StorageConfig",
    "save_config",
    "load_config",
]
