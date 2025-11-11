"""Data models for job roles and employees."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


def _unique_preserve(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        cleaned = str(value or "").strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def normalize_person_name(raw: str) -> str:
    stripped = (raw or "").strip()
    if not stripped:
        return ""

    def _capitalize_segment(segment: str) -> str:
        return "-".join(part.capitalize() for part in segment.split("-"))

    return " ".join(_capitalize_segment(part) for part in stripped.split())


@dataclass
class LicenseSelection:
    """Represents a Microsoft 365 license selection with disabled service plans."""

    sku_id: str
    disabled_plans: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LicenseSelection":
        sku = str(
            data.get("sku_id")
            or data.get("sku")
            or data.get("id")
            or data.get("licenseSku")
            or ""
        ).strip()
        disabled = data.get("disabled_plans") or data.get("disabled_service_plans") or []
        return cls(sku_id=sku, disabled_plans=list(disabled))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sku_id": self.sku_id,
            "disabled_plans": list(self.disabled_plans),
        }

    def normalized(self) -> "LicenseSelection":
        return LicenseSelection(sku_id=self.sku_id.strip(), disabled_plans=_unique_preserve(self.disabled_plans))


@dataclass
class JobRole:
    """Represents a reusable onboarding template for a specific job role."""

    name: str
    description: Optional[str] = None
    user_ou: Optional[str] = None
    default_manager_dn: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    groups: List[str] = field(default_factory=list)
    licenses: List[LicenseSelection] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JobRole":
        legacy_sku = str(data.get("license_sku_id") or "").strip()
        legacy_plans = data.get("disabled_service_plans") or []
        licenses_data = data.get("licenses")
        resolved: List[LicenseSelection] = []

        if isinstance(licenses_data, list):
            for entry in licenses_data:
                try:
                    selection = LicenseSelection.from_dict(entry).normalized()
                except Exception:
                    continue
                if selection.sku_id:
                    resolved.append(selection)
        elif legacy_sku:
            resolved.append(
                LicenseSelection(sku_id=legacy_sku, disabled_plans=list(legacy_plans)).normalized()
            )

        return cls(
            name=data["name"],
            description=data.get("description"),
            user_ou=data.get("user_ou"),
            default_manager_dn=data.get("default_manager_dn"),
            attributes=dict(data.get("attributes", {})),
            groups=list(data.get("groups", [])),
            licenses=resolved,
        )

    def to_dict(self) -> Dict[str, Any]:
        primary = self.primary_license
        payload: Dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "user_ou": self.user_ou,
            "default_manager_dn": self.default_manager_dn,
            "attributes": dict(self.attributes),
            "groups": list(self.groups),
            "licenses": [selection.normalized().to_dict() for selection in self.licenses],
        }
        payload["license_sku_id"] = primary.sku_id if primary else None
        payload["disabled_service_plans"] = list(primary.disabled_plans) if primary else []
        return payload

    @property
    def primary_license(self) -> Optional[LicenseSelection]:
        return self.licenses[0] if self.licenses else None

    @property
    def license_sku_id(self) -> Optional[str]:
        primary = self.primary_license
        return primary.sku_id if primary else None

    @license_sku_id.setter
    def license_sku_id(self, value: Optional[str]) -> None:
        sku = str(value or "").strip()
        if not sku:
            self.licenses = []
            return
        primary = self.primary_license
        disabled = list(primary.disabled_plans) if primary else []
        self.licenses = [LicenseSelection(sku_id=sku, disabled_plans=disabled)]

    @property
    def disabled_service_plans(self) -> List[str]:
        primary = self.primary_license
        return list(primary.disabled_plans) if primary else []

    @disabled_service_plans.setter
    def disabled_service_plans(self, plans: Iterable[str]) -> None:
        primary = self.primary_license
        sku = primary.sku_id if primary else None
        if not sku:
            return
        self.licenses = [LicenseSelection(sku_id=sku, disabled_plans=_unique_preserve(plans or []))]


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
    groups: List[str] = field(default_factory=list)
    licenses: List[LicenseSelection] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.first_name = normalize_person_name(self.first_name)
        self.last_name = normalize_person_name(self.last_name)
        cleaned: List[LicenseSelection] = []
        for selection in self.licenses:
            if selection and selection.sku_id:
                cleaned.append(selection.normalized())
        self.licenses = cleaned

    @property
    def display_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    def distinguished_name(self, user_ou: str, base_dn: str) -> str:
        container = user_ou if user_ou else base_dn
        return f"CN={self.display_name},{container}"

    @property
    def primary_license(self) -> Optional[LicenseSelection]:
        return self.licenses[0] if self.licenses else None

    @property
    def license_sku_id(self) -> Optional[str]:
        primary = self.primary_license
        return primary.sku_id if primary else None

    @license_sku_id.setter
    def license_sku_id(self, value: Optional[str]) -> None:
        sku = str(value or "").strip()
        if not sku:
            self.licenses = []
            return
        primary = self.primary_license
        disabled = list(primary.disabled_plans) if primary else []
        self.licenses = [LicenseSelection(sku_id=sku, disabled_plans=disabled)]

    @property
    def disabled_service_plans(self) -> List[str]:
        primary = self.primary_license
        return list(primary.disabled_plans) if primary else []

    @disabled_service_plans.setter
    def disabled_service_plans(self, plans: Iterable[str]) -> None:
        primary = self.primary_license
        sku = primary.sku_id if primary else None
        if not sku:
            return
        self.licenses = [LicenseSelection(sku_id=sku, disabled_plans=_unique_preserve(plans or []))]


__all__ = ["Employee", "JobRole", "LicenseSelection", "normalize_person_name"]
