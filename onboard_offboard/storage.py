"""Persistence helpers for storing job roles."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List

import yaml

from .models import JobRole


def load_job_roles(path: Path) -> Dict[str, JobRole]:
    """Load job roles from a YAML file."""

    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}

    roles_data: Iterable[dict] = payload.get("roles", [])
    roles: Dict[str, JobRole] = {}
    for entry in roles_data:
        role = JobRole.from_dict(entry)
        roles[role.name] = role
    return roles


def save_job_roles(path: Path, roles: Dict[str, JobRole]) -> None:
    """Persist job roles to disk."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"roles": [role.to_dict() for role in roles.values()]}
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False)


def list_job_role_names(roles: Dict[str, JobRole]) -> List[str]:
    return sorted(roles.keys())


__all__ = ["load_job_roles", "save_job_roles", "list_job_role_names"]
