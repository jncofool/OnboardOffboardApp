"""Sync command helpers shared by the CLI and web application."""
from __future__ import annotations

import shlex
import subprocess

from .config import SyncConfig


def run_sync_command(sync: SyncConfig) -> None:
    """Execute the configured directory sync command and surface friendly errors."""

    if not sync.command:
        return

    try:
        subprocess.run(
            sync.command if sync.shell else shlex.split(sync.command),
            shell=sync.shell,
            timeout=sync.timeout,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Sync command not found: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Sync command failed with exit code {exc.returncode}.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Sync command timed out.") from exc


__all__ = ["run_sync_command"]
