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
    group_search_base: Optional[str] = None


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
    license_jobs_file: Path = Path("data/license_jobs.json")


@dataclass
class M365Config:
    """Settings for the Microsoft 365 / Graph integration."""

    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    sku_cache_file: Path = field(default_factory=lambda: Path("data/m365_skus.json"))
    cache_ttl_minutes: int = 720  # 12 hours by default
    default_usage_location: Optional[str] = None

    @property
    def has_credentials(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)


@dataclass
@dataclass
class AuthConfig:
    """Settings for Entra ID / Microsoft identity authentication."""

    enabled: bool = False
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None
    allowed_groups: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ("https://graph.microsoft.com/User.Read",)

    @property
    def has_credentials(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)


@dataclass
class AppConfig:
    """Aggregate configuration for the application."""

    ldap: LDAPConfig
    sync: SyncConfig
    storage: StorageConfig = field(default_factory=StorageConfig)
    m365: M365Config = field(default_factory=M365Config)
    auth: AuthConfig = field(default_factory=AuthConfig)


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


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return str(value)


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
            group_search_base=(ldap_section.get("group_search_base") or None),
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
        job_roles_file=Path(storage_section.get("job_roles_file", StorageConfig().job_roles_file)),
        license_jobs_file=Path(
            storage_section.get("license_jobs_file", StorageConfig().license_jobs_file)
        ),
    )

    m365_section = config_dict.get("m365", {})
    default_m365 = M365Config()
    cache_path = _optional_path(m365_section.get("sku_cache_file")) or default_m365.sku_cache_file
    cache_ttl_raw = m365_section.get("cache_ttl_minutes", default_m365.cache_ttl_minutes)
    try:
        cache_ttl = _to_int(cache_ttl_raw)
    except Exception:
        cache_ttl = default_m365.cache_ttl_minutes
    m365_config = M365Config(
        tenant_id=_optional_str(m365_section.get("tenant_id")),
        client_id=_optional_str(m365_section.get("client_id")),
        client_secret=_optional_str(m365_section.get("client_secret")),
        sku_cache_file=cache_path,
        cache_ttl_minutes=cache_ttl,
        default_usage_location=_optional_str(m365_section.get("default_usage_location")),
    )

    auth_section = config_dict.get("auth", {})
    allowed_groups = tuple(
        filter(
            None,
            [
                entry.strip()
                for entry in _normalize_sequence(auth_section.get("allowed_groups", ()))
            ],
        )
    )
    scopes = tuple(
        filter(
            None,
            [
                entry.strip()
                for entry in _normalize_sequence(
                    auth_section.get("scopes", ("https://graph.microsoft.com/User.Read",))
                )
            ],
        )
    ) or ("https://graph.microsoft.com/User.Read",)
    auth_config = AuthConfig(
        enabled=_to_bool(auth_section.get("enabled", False)),
        tenant_id=_optional_str(auth_section.get("tenant_id")),
        client_id=_optional_str(auth_section.get("client_id")),
        client_secret=_optional_str(auth_section.get("client_secret")),
        redirect_uri=_optional_str(auth_section.get("redirect_uri")),
        allowed_groups=allowed_groups,
        scopes=scopes,
    )

    return AppConfig(
        ldap=ldap_config,
        sync=sync_config,
        storage=storage_config,
        m365=m365_config,
        auth=auth_config,
    )


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
            **(
                {"group_search_base": config.ldap.group_search_base}
                if config.ldap.group_search_base
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
            "license_jobs_file": str(config.storage.license_jobs_file),
        },
        "m365": {
            "tenant_id": config.m365.tenant_id or "",
            "client_id": config.m365.client_id or "",
            "client_secret": config.m365.client_secret or "",
            "sku_cache_file": str(config.m365.sku_cache_file),
            "cache_ttl_minutes": config.m365.cache_ttl_minutes,
            "default_usage_location": config.m365.default_usage_location or "",
<<<<<<< HEAD
        },
        "auth": {
            "enabled": config.auth.enabled,
            "tenant_id": config.auth.tenant_id or "",
            "client_id": config.auth.client_id or "",
            "client_secret": config.auth.client_secret or "",
            "redirect_uri": config.auth.redirect_uri or "",
            "allowed_groups": list(config.auth.allowed_groups),
            "scopes": list(config.auth.scopes),
=======
>>>>>>> a19a8e30961c2a13928b25dd6d1a7f5bab9d820e
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
    "M365Config",
    "AuthConfig",
    "save_config",
    "load_config",
]
