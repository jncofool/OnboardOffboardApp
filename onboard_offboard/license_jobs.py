"""Persistence helpers for Microsoft 365 license assignment jobs."""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


@dataclass
class LicenseJob:
    """Represents an outstanding Microsoft 365 license assignment request."""

    id: str
    principal: str
    sku_id: str
    principal_candidates: List[str] = field(default_factory=list)
    disabled_plans: List[str] = field(default_factory=list)
    azure_groups: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, completed, failed
    attempts: int = 0
    created_at: datetime = field(default_factory=_utc_now)
    not_before: datetime = field(default_factory=_utc_now)
    last_attempt_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "principal": self.principal,
            "sku_id": self.sku_id,
            "principal_candidates": list(self.principal_candidates),
            "disabled_plans": list(self.disabled_plans),
            "azure_groups": list(self.azure_groups),
            "status": self.status,
            "attempts": self.attempts,
            "created_at": self.created_at.isoformat(),
            "not_before": self.not_before.isoformat(),
            "last_attempt_at": self.last_attempt_at.isoformat() if self.last_attempt_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "LicenseJob":
        return cls(
            id=str(data.get("id") or uuid.uuid4()),
            principal=str(data["principal"]),
            sku_id=str(data["sku_id"]),
            principal_candidates=list(data.get("principal_candidates") or []),
            disabled_plans=list(data.get("disabled_plans") or []),
            azure_groups=list(data.get("azure_groups") or []),
            status=str(data.get("status") or "pending"),
            attempts=int(data.get("attempts") or 0),
            created_at=_parse_datetime(data.get("created_at")) or _utc_now(),
            not_before=_parse_datetime(data.get("not_before")) or (_utc_now() + timedelta(seconds=90)),
            last_attempt_at=_parse_datetime(data.get("last_attempt_at")),
            completed_at=_parse_datetime(data.get("completed_at")),
            last_error=str(data.get("last_error")) if data.get("last_error") else None,
        )


class LicenseJobStore:
    """Thread-safe store for license assignment jobs."""

    def __init__(self, path: Path, max_attempts: int = 10) -> None:
        self.path = path
        self.max_attempts = max_attempts
        self._lock = threading.Lock()
        self._jobs: Dict[str, LicenseJob] = {}
        self._load()

    # ------------------------------------------------------------------ #
    # Persistence                                                        #
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._jobs = {}
            return
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle) or {}
        except (OSError, ValueError):
            payload = {}
        jobs = payload.get("jobs") or []
        self._jobs = {}
        for entry in jobs:
            try:
                job = LicenseJob.from_dict(entry)
                self._jobs[job.id] = job
            except Exception:
                continue

    def _save(self) -> None:
        payload = {"jobs": [job.to_dict() for job in self._jobs.values()]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        tmp_path.replace(self.path)

    # ------------------------------------------------------------------ #
    # Job management                                                     #
    # ------------------------------------------------------------------ #
    def add_job(
        self,
        principal: str,
        sku_id: str,
        disabled_plans: Iterable[str],
        alternates: Iterable[str] = (),
        azure_groups: Iterable[str] = (),
        delay_seconds: int = 0,
    ) -> LicenseJob:
        with self._lock:
            candidate_set: List[str] = []
            seen_lower: set[str] = {principal.strip().lower()}
            for candidate in alternates or []:
                cleaned = str(candidate or "").strip()
                if not cleaned:
                    continue
                lowered = cleaned.lower()
                if lowered in seen_lower:
                    continue
                seen_lower.add(lowered)
                candidate_set.append(cleaned)
            job = LicenseJob(
                id=str(uuid.uuid4()),
                principal=principal,
                sku_id=sku_id,
                principal_candidates=candidate_set,
                disabled_plans=list(disabled_plans or []),
                azure_groups=list(azure_groups or []),
            )
            if delay_seconds > 0:
                job.not_before = _utc_now() + timedelta(seconds=delay_seconds)
            self._jobs[job.id] = job
            self._save()
            return job

    def pending_jobs(self) -> List[LicenseJob]:
        now = _utc_now()
        with self._lock:
            jobs = [
                job
                for job in self._jobs.values()
                if job.status == "pending" and job.not_before <= now
            ]
            jobs.sort(key=lambda job: job.created_at)
            return [LicenseJob.from_dict(job.to_dict()) for job in jobs]  # return copies

    def mark_completed(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = "completed"
            job.completed_at = _utc_now()
            job.last_error = None
            self._save()

    def defer_job(self, job_id: str, delay: timedelta, error: Optional[str]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.attempts += 1
            job.last_attempt_at = _utc_now()
            job.not_before = job.last_attempt_at + delay
            job.last_error = error
            if job.attempts >= self.max_attempts:
                job.status = "failed"
            self._save()

    def reset_from_copy(self, job: LicenseJob) -> None:
        """Replace stored job with supplied copy (after external mutation)."""

        with self._lock:
            self._jobs[job.id] = job
            self._save()
