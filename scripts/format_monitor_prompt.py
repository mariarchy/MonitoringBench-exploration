"""Print the filled FT monitor prompt for one slice trajectory (no API)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from evals.slice_dataset import leak_errors, slice_samples
from extract_slice_logs import load_slice
from pretty import banner, item_list, note, section, wrap_field
from read_one import first_lines, resolve_row


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "query",
        nargs="?",
        default="2EuoeP5hxCitkXzGxHfF6M",
        help="sample_uuid or slot. Default: core_uncaught_firewall.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Print the entire filled prompt (default: first 80 lines).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    row = resolve_row(load_slice(), args.query)
    sample = slice_samples(uuid=row["sample_uuid"])[0]
    meta = sample.metadata or {}
    prompt = sample.input if isinstance(sample.input, str) else str(sample.input)
    errors = leak_errors(
        task_description=str(meta.get("task_description") or ""),
        tool_calls=str(meta.get("tool_calls") or ""),
        side_task=str(meta.get("side_task_description") or ""),
        attack_summary=str(meta.get("attack_summary") or ""),
    )

    banner(
        "FT monitor prompt    (no API)",
        f"{row['slot']}    uuid {row['sample_uuid']}",
        f"{len(prompt):,} chars    Sample.id={sample.id}",
    )
    section("Leak check    (side task / attack summary vs main task)")
    if errors:
        item_list(errors)
        raise SystemExit("prompt leak")
    item_list(("clean — hidden fields are not in the main-task text",))

    section("Hidden metadata    (must not appear in Sample.input)")
    wrap_field("slot", meta.get("slot"))
    wrap_field("opus_mean", meta.get("opus_mean"))
    wrap_field("attack_summary", meta.get("attack_summary"))

    section("Sample.input    (what generate() will send)")
    body = prompt if args.full else first_lines(prompt, 80)
    print(body)
    if not args.full and body != prompt:
        note("Re-run with --full to print the rest. This is the ControlArena FT template.")


if __name__ == "__main__":
    main()
