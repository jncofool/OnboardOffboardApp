"""Microsoft 365 Graph helper utilities."""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import msal
import requests

from .config import M365Config


GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
REQUEST_TIMEOUT = 30


class M365ClientError(RuntimeError):
    """Base exception for Microsoft 365 client operations."""


class M365ConfigurationError(M365ClientError):
    """Raised when the Microsoft 365 integration is not configured."""


class M365GraphError(M365ClientError):
    """Raised when the Microsoft Graph API returns an error."""

    def __init__(self, status_code: int, error: str, description: str) -> None:
        super().__init__(f"{status_code}: {error} - {description}")
        self.status_code = status_code
        self.error = error
        self.description = description


@dataclass(frozen=True)
class CatalogSnapshot:
    fetched_at: datetime
    skus: List[Dict[str, Any]]
    stale: bool


class M365Client:
    """Lightweight Microsoft Graph client with SKU catalog caching."""

    def __init__(self, config: M365Config) -> None:
        if not config.has_credentials:
            raise M365ConfigurationError(
                "Microsoft 365 credentials are not configured. "
                "Provide tenant_id, client_id, and client_secret."
            )

        self._config = config
        self._authority = f"https://login.microsoftonline.com/{config.tenant_id}"
        self._app = msal.ConfidentialClientApplication(
            client_id=config.client_id,
            client_credential=config.client_secret,
            authority=self._authority,
        )
        self._token_lock = threading.Lock()
        self._session = requests.Session()

    # ------------------------------------------------------------------ #
    # Token handling / HTTP helpers                                      #
    # ------------------------------------------------------------------ #
    def _acquire_token(self) -> str:
        with self._token_lock:
            result = self._app.acquire_token_silent(GRAPH_SCOPE, account=None)
            if not result:
                result = self._app.acquire_token_for_client(scopes=GRAPH_SCOPE)

        if "access_token" not in result:
            raise M365GraphError(
                status_code=0,
                error=result.get("error", "token_error"),
                description=result.get("error_description", "Unable to acquire Graph token."),
            )
        return str(result["access_token"])

    def _request(self, method: str, path: str, **kwargs: Any) -> Dict[str, Any]:
        url = GRAPH_BASE_URL + path
        headers = kwargs.pop("headers", {}) or {}
        headers.setdefault("Authorization", f"Bearer {self._acquire_token()}")
        headers.setdefault("Accept", "application/json")
        if "json" in kwargs:
            headers.setdefault("Content-Type", "application/json")

        response = self._session.request(
            method,
            url,
            timeout=REQUEST_TIMEOUT,
            headers=headers,
            **kwargs,
        )
        if response.status_code == 204:
            return {}

        if response.status_code >= 400:
            try:
                payload = response.json()
                error = payload.get("error", {})
                code = error.get("code", "GraphError")
                message = error.get("message", response.text)
            except ValueError:
                code = "GraphError"
                message = response.text or "Unknown Graph error."
            raise M365GraphError(response.status_code, code, message)

        return response.json()

    # ------------------------------------------------------------------ #
    # SKU catalog management                                             #
    # ------------------------------------------------------------------ #
    @property
    def cache_path(self) -> Path:
        return self._config.sku_cache_file

    @property
    def cache_ttl(self) -> timedelta:
        minutes = max(1, int(self._config.cache_ttl_minutes or 0))
        return timedelta(minutes=minutes)

    def list_subscribed_skus(self) -> List[Dict[str, Any]]:
        result = self._request(
            "GET",
            "/subscribedSkus",
            params={
                "$select": "id,skuId,skuPartNumber,capabilityStatus,prepaidUnits,appliesTo,"
                "consumedUnits,servicePlans",
            },
        )
        return result.get("value", [])

    def get_sku_catalog(self, force_refresh: bool = False) -> CatalogSnapshot:
        cached = self.peek_cached_catalog()
        if cached and not force_refresh and not cached.stale:
            return cached

        skus = self.list_subscribed_skus()
        snapshot = CatalogSnapshot(
            fetched_at=datetime.now(timezone.utc),
            skus=skus,
            stale=False,
        )
        self._write_catalog(snapshot)
        return snapshot

    def refresh_sku_catalog(self) -> CatalogSnapshot:
        return self.get_sku_catalog(force_refresh=True)

    def peek_cached_catalog(self) -> Optional[CatalogSnapshot]:
        data = self._read_catalog()
        if not data:
            return None
        fetched_at = self._parse_timestamp(data.get("fetched_at"))
        if not fetched_at:
            return None
        stale = datetime.now(timezone.utc) - fetched_at > self.cache_ttl
        skus = data.get("skus") or []
        return CatalogSnapshot(fetched_at=fetched_at, skus=skus, stale=stale)

    # ------------------------------------------------------------------ #
    # User helpers (used in later steps)                                 #
    # ------------------------------------------------------------------ #
    def find_user(self, query: str, select: Optional[str] = None) -> Optional[Dict[str, Any]]:
        params = {"$filter": f"userPrincipalName eq '{query}'"}
        if select:
            params["$select"] = select
        result = self._request("GET", "/users", params=params)
        values = result.get("value") or []
        return values[0] if values else None

    def get_user_license_details(self, user_id: str) -> List[Dict[str, Any]]:
        result = self._request("GET", f"/users/{user_id}/licenseDetails")
        return result.get("value", [])

    def assign_license(
        self,
        user_id: str,
        sku_id: str,
        disabled_plans: Optional[Iterable[str]] = None,
        remove_skus: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "addLicenses": [
                {
                    "skuId": sku_id,
                    "disabledPlans": list(disabled_plans or []),
                }
            ],
            "removeLicenses": list(remove_skus or []),
        }
        return self._request("POST", f"/users/{user_id}/assignLicense", json=payload)

    # ------------------------------------------------------------------ #
    # Cache read/write helpers                                           #
    # ------------------------------------------------------------------ #
    def _read_catalog(self) -> Optional[Dict[str, Any]]:
        path = self.cache_path
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return None

    def _write_catalog(self, snapshot: CatalogSnapshot) -> None:
        payload = {
            "fetched_at": snapshot.fetched_at.isoformat(),
            "skus": snapshot.skus,
        }
        path = self.cache_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    @staticmethod
    def _parse_timestamp(raw: Any) -> Optional[datetime]:
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(str(raw))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None


__all__ = [
    "M365Client",
    "M365ClientError",
    "M365ConfigurationError",
    "M365GraphError",
    "CatalogSnapshot",
]
