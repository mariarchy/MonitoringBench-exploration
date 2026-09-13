"""Live debate on all 12 slice trajectories (36 API calls)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from inspect_ai import eval as inspect_eval

REPO_ROOT = Path(__file__).resolve().parents[1]
os.chdir(REPO_ROOT)
os.environ.setdefault("INSPECT_TRACE_FILE", str(REPO_ROOT / "logs" / "inspect-trace.log"))
load_dotenv(REPO_ROOT / ".env")
sys.path.insert(0, str(REPO_ROOT / "evals"))

from constants import OPUS_MODEL  # noqa: E402


def main() -> None:
    logs = inspect_eval(
        "evals/debate_monitor.py",
        model=OPUS_MODEL,
        log_dir="logs",
        max_connections=2,
        tags=["debate-phase1-slice"],
    )
    log = logs[0]
    n = len(log.samples or [])
    location = getattr(log, "location", None) or log.eval.eval_id
    print(f"debate_monitor samples {n}    log {location}")
    print("Next: uv run python scripts/compare_debate.py")


if __name__ == "__main__":
    main()
