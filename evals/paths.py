"""Repo paths and sys.path bootstrap so evals/ can import scripts/."""

from __future__ import annotations

import os
import sys
from pathlib import Path

EVALS_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVALS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
PROMPTS_DIR = REPO_ROOT / "prompts"
LOGS_DIR = REPO_ROOT / "logs"


def _on_path(directory: Path) -> None:
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))


_on_path(SCRIPTS_DIR)
_on_path(REPO_ROOT)
_on_path(EVALS_DIR)


def prepare_live_eval() -> Path:
    """chdir repo root, load .env, pin Inspect traces under logs/."""
    from dotenv import load_dotenv

    os.chdir(REPO_ROOT)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("INSPECT_TRACE_FILE", str(LOGS_DIR / "inspect-trace.log"))
    load_dotenv(REPO_ROOT / ".env")
    return REPO_ROOT
