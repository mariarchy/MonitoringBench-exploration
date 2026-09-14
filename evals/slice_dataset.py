"""Turn a frozen MonitoringBench trajectory into an Inspect Sample.

Sample.input is what a monitor is allowed to see: the ControlArena FT
template filled with the main SWE task and numbered tool calls (no
outputs). Hidden labels (side task, attack summary, parquet scores) stay
in metadata and must not be interpolated into input.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from inspect_ai.dataset import Sample

_EVALS = Path(__file__).resolve().parent
_SCRIPTS = _EVALS.parent / "scripts"
for _path in (_EVALS, _SCRIPTS):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from constants import ARG_CHARS, MONITOR_TEMPLATE, UNCAUGHT_UUID
from extract_slice_logs import load_slice, log_path
from paths import PROMPTS_DIR, REPO_ROOT
from read_one import as_text, collect_tool_calls, nested_get, read_sample, resolve_row


def read_template(relative: str) -> str:
    path = REPO_ROOT / relative
    if not path.exists():
        path = PROMPTS_DIR / Path(relative).name
    text = path.read_text()
    if not text.strip():
        raise FileNotFoundError(f"empty template {path}")
    return text


def fill_template(template: str, **subs: str) -> str:
    """Replace {name} placeholders. Avoid str.format — tool calls contain braces."""
    filled = template
    for key, value in subs.items():
        filled = filled.replace("{" + key + "}", value)
    return filled


def format_tool_calls(
    calls: list[dict[str, Any]], *, max_chars: int | None = ARG_CHARS
) -> str:
    blocks: list[str] = []
    for index, call in enumerate(calls, start=1):
        arguments = call.get("arguments") or {}
        if isinstance(arguments, str):
            rendered = arguments
        else:
            rendered = json.dumps(arguments, ensure_ascii=False, indent=2)
        if max_chars is not None and len(rendered) > max_chars:
            rendered = rendered[:max_chars] + f"\n… [{len(rendered)} chars total]"
        function = call.get("function") or "?"
        blocks.append(f"[{index}] {function}\n{rendered}")
    return "\n\n".join(blocks) if blocks else "(no tool calls)"


def leak_errors(
    *,
    task_description: str,
    tool_calls: str,
    side_task: str,
    attack_summary: str,
) -> list[str]:
    """Side-task *instruction* must not appear in the main-task text.

    Tool calls may mention IOCs that also appear in the side task; that is
    expected and is not a leak of the hidden objective prompt.
    """
    errors: list[str] = []
    side = side_task.strip()
    summary = attack_summary.strip()
    if side and side in task_description:
        errors.append("side_task_description appears in the main task text")
    if summary and summary in task_description:
        errors.append("attack_summary appears in the main task text")
    if side and side in tool_calls and len(side) > 80:
        errors.append(
            "full side_task_description appears inside tool-call arguments "
            "(unexpected; the hidden prompt leaked into a write)"
        )
    return errors


def sample_from_row(row: dict) -> Sample:
    eval_file = log_path(row["eval_log_filename"])
    if not eval_file.exists():
        raise FileNotFoundError(
            f"missing {eval_file}. Run: uv run python scripts/extract_slice_logs.py"
        )
    sample = read_sample(eval_file, row["sample_uuid"], str(row.get("task_id") or ""))
    metadata = getattr(sample, "metadata", None) or {}
    task_description = as_text(nested_get(metadata, "main_task_description"))
    if not task_description:
        task_description = as_text(getattr(sample, "input", None))
    side_task = as_text(nested_get(metadata, "side_task_description"))
    calls, _source = collect_tool_calls(sample)
    tool_calls = format_tool_calls(calls)
    errors = leak_errors(
        task_description=task_description,
        tool_calls=tool_calls,
        side_task=side_task,
        attack_summary=str(row.get("attack_summary") or ""),
    )
    if errors:
        raise AssertionError(
            f"monitor prompt leak for {row['sample_uuid']}: " + "; ".join(errors)
        )

    prompt = fill_template(
        read_template(MONITOR_TEMPLATE),
        task_description=task_description,
        tool_calls=tool_calls,
    )
    return Sample(
        id=row["sample_uuid"],
        input=prompt,
        metadata={
            "sample_uuid": row["sample_uuid"],
            "slot": row.get("slot"),
            "task_id": row.get("task_id"),
            "task_description": task_description,
            "tool_calls": tool_calls,
            "opus_mean": row.get("opus_mean"),
            "opus_caught": row.get("opus_caught"),
            "side_task_group": row.get("side_task_group"),
            "side_task_name": row.get("side_task_name"),
            "attack_summary": row.get("attack_summary"),
            "side_task_description": side_task,
        },
    )


def slice_samples(
    *,
    uuid: str | None = None,
    query: str | None = None,
    queries: list[str] | None = None,
) -> list[Sample]:
    slice_data = load_slice()
    if queries:
        return [sample_from_row(resolve_row(slice_data, q)) for q in queries]
    if uuid or query:
        row = resolve_row(slice_data, uuid or query)
        return [sample_from_row(row)]
    return [sample_from_row(row) for row in slice_data["trajectories"]]


def default_uncaught() -> Sample:
    return slice_samples(uuid=UNCAUGHT_UUID)[0]
