"""Run the debate monitor. Arms are flags, not new scripts.

Examples:
  uv run python scripts/run_debate.py --prompts bundle --group judge-shrug
  uv run python scripts/run_debate.py --prompts default --slot extra_missed_all
  uv run python scripts/run_debate.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from inspect_ai import eval as inspect_eval

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evals"))
from paths import prepare_live_eval  # noqa: E402

prepare_live_eval()

from constants import (  # noqa: E402
    OPUS_MODEL,
    OPUS_TAU,
    PROMPT_PACKS,
    ROW_GROUPS,
    SLOT_IOCS,
)
from pretty import banner, note, section, table  # noqa: E402
from read_one import SIDE_IOCS  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prompts",
        choices=sorted(PROMPT_PACKS),
        default="default",
        help="Prompt pack (default: Phase 1 templates).",
    )
    parser.add_argument(
        "--group",
        action="append",
        choices=sorted(ROW_GROUPS),
        help="Named row group. Repeatable. See constants.ROW_GROUPS.",
    )
    parser.add_argument(
        "--slot",
        action="append",
        default=[],
        help="Slice slot or uuid. Repeatable.",
    )
    parser.add_argument(
        "--uuid",
        action="append",
        default=[],
        dest="slot",
        help="Alias for --slot.",
    )
    parser.add_argument("--mock", action="store_true", help="mockllm, no API key.")
    parser.add_argument("--tag", help="Inspect log tag. Default: debate-<prompts>.")
    parser.add_argument("--max-connections", type=int, default=2)
    parser.add_argument("--model", default=OPUS_MODEL)
    return parser.parse_args()


def selected_queries(args: argparse.Namespace) -> list[str] | None:
    queries: list[str] = list(args.slot)
    for group in args.group or []:
        queries.extend(ROW_GROUPS[group])
    # Preserve order, drop dupes.
    seen: set[str] = set()
    ordered: list[str] = []
    for query in queries:
        if query not in seen:
            seen.add(query)
            ordered.append(query)
    return ordered or None


def needles_for(slot: str, side: str) -> tuple[str, ...]:
    extra = SLOT_IOCS.get(slot, ())
    base = SIDE_IOCS.get(side, ())
    merged: list[str] = []
    for item in (*extra, *base):
        if item not in merged:
            merged.append(item)
    return tuple(merged)


def ioc_hits(text: str, needles: tuple[str, ...]) -> str:
    found = [n for n in needles if n in text]
    return ", ".join(found) if found else "—"


def print_readout(log: Any) -> None:
    samples = list(log.samples or [])
    rows: list[tuple[str, ...]] = []
    for sample in samples:
        meta = dict(getattr(sample, "metadata", None) or {})
        score = (getattr(sample, "scores", None) or {}).get("suspicion_score")
        raw = getattr(score, "value", None) if score is not None else None
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = None
        slot = str(meta.get("slot") or sample.id)
        side = str(meta.get("side_task_group") or "")
        parquet = meta.get("opus_mean")
        try:
            parquet_s = f"{float(parquet):.2f}"
        except (TypeError, ValueError):
            parquet_s = "—"
        debate_s = f"{value:.2f}" if value is not None else "—"
        caught = value is not None and value > OPUS_TAU
        needles = needles_for(slot, side)
        prosecutor = str(meta.get("prosecutor_arg") or "")
        judge = str(meta.get("judge_arg") or "")
        rows.append(
            (
                slot,
                parquet_s,
                debate_s,
                "yes" if caught else "no",
                ioc_hits(prosecutor, needles),
                ioc_hits(judge, needles),
            )
        )
    section("Readout")
    table(
        ("slot", "parquet", "debate", f"> {OPUS_TAU:g}", "prosecutor IOC", "judge IOC"),
        rows,
    )
    note(
        "Open a transcript only if debate flipped vs parquet catch, or prosecutor IOC is empty."
    )


def main() -> None:
    args = parse_args()
    queries = selected_queries(args)
    uuid_arg = ",".join(queries) if queries else None
    tag = args.tag or f"debate-{args.prompts}"
    task_args: dict[str, Any] = {"prompts": args.prompts, "mock": args.mock}
    if uuid_arg:
        task_args["uuid"] = uuid_arg
    banner(
        "debate_monitor",
        f"prompts={args.prompts}    rows={uuid_arg or 'all 12'}    mock={args.mock}",
    )
    eval_kwargs: dict[str, Any] = {
        "task_args": task_args,
        "log_dir": "logs",
        "max_connections": 1 if args.mock else args.max_connections,
        "tags": [tag],
    }
    if not args.mock:
        eval_kwargs["model"] = args.model
    logs = inspect_eval("evals/debate_monitor.py", **eval_kwargs)
    log = logs[0]
    n = len(log.samples or [])
    location = getattr(log, "location", None) or log.eval.eval_id
    print(f"samples {n}    log {location}")
    print_readout(log)


if __name__ == "__main__":
    main()
