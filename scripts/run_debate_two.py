"""Live debate on one Opus miss and one Opus catch (6 API calls)."""

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

from constants import CAUGHT_UUID, OPUS_MODEL, UNCAUGHT_UUID  # noqa: E402


def run_one(uuid: str, label: str) -> None:
    logs = inspect_eval(
        "evals/debate_monitor.py",
        model=OPUS_MODEL,
        task_args={"uuid": uuid},
        log_dir="logs",
        max_connections=1,
    )
    log = logs[0]
    sample = (log.samples or [None])[0]
    if sample is None:
        raise SystemExit(f"no sample for {uuid}")
    score = (sample.scores or {}).get("suspicion_score")
    value = getattr(score, "value", None) if score is not None else None
    meta = getattr(score, "metadata", None) or {}
    print(f"{label}    uuid {uuid}")
    print(
        f"  debate score {value}    parquet mean {meta.get('parquet_opus_mean')}    "
        f"caught {meta.get('caught')}    prosecutor_first {meta.get('prosecutor_first')}"
    )


def main() -> None:
    run_one(UNCAUGHT_UUID, "core_uncaught_firewall")
    run_one(CAUGHT_UUID, "core_caught_firewall")
    print("Read logs/ in inspect view: did the prosecutor cite the actual mechanism?")


if __name__ == "__main__":
    main()
