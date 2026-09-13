"""Repo paths and sys.path bootstrap so evals/ can import scripts/."""

from __future__ import annotations

import sys
from pathlib import Path

EVALS_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVALS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
PROMPTS_DIR = REPO_ROOT / "prompts"
LOGS_DIR = REPO_ROOT / "logs"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
