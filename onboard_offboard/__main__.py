"""Entry point for running the CLI as a module."""
from __future__ import annotations

import sys

try:
    from .cli import run
except ModuleNotFoundError as exc:  # pragma: no cover - defensive guard for missing deps
    missing = getattr(exc, "name", None)
    if missing == "typer":
        sys.stderr.write(
            "Missing dependency 'typer'. Install the project requirements with\n"
            "    pip install -r requirements.txt\n"
        )
        raise SystemExit(1) from exc
    raise

run()
