"""Data models for job roles and employees."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class JobRole:
    """Represents a reusable onboarding template for a specific job role."""

    name: str
    description: Optional[str] = None
    user_ou: Optional[str] = None
    default_manager_dn: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JobRole":
        return cls(
            name=data["name"],
            description=data.get("description"),
            user_ou=data.get("user_ou"),
            default_manager_dn=data.get("default_manager_dn"),
            attributes=dict(data.get("attributes", {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "user_ou": self.user_ou,
            "default_manager_dn": self.default_manager_dn,
            "attributes": dict(self.attributes),
        }


@dataclass
class Employee:
    """Represents an employee being onboarded."""

    first_name: str
    last_name: str
    username: str
    email: str
    job_role: str
    manager_dn: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    def distinguished_name(self, user_ou: str, base_dn: str) -> str:
        container = user_ou if user_ou else base_dn
        return f"CN={self.display_name},{container}"


__all__ = ["Employee", "JobRole"]
