"""Name the Inspect objects inside one frozen MonitoringBench .eval log.

This log is an *attack-agent* eval: the solver (when present) was the
untrusted BashArena policy. Its scorers are programmatic side/main-task
checks plus any in-log monitors. Later chunks write a different kind of
.eval — a *monitor* eval that only scores the frozen tool-call list.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from extract_slice_logs import load_slice, log_path
from pretty import banner, item_list, note, section, table
from read_one import collect_tool_calls, resolve_row

DEFAULT_QUERY = "2EuoeP5hxCitkXzGxHfF6M"


def parse_args() -> str:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "query",
        nargs="?",
        default=DEFAULT_QUERY,
        help="sample_uuid (prefix ok) or slot. Default: core_uncaught_firewall.",
    )
    return parser.parse_args().query


def attr(obj: Any, name: str) -> str:
    value = getattr(obj, name, None)
    if value is None or value == "":
        return "—"
    return str(value)


def main() -> None:
    query = parse_args()
    slice_data = load_slice()
    row = resolve_row(slice_data, query)
    eval_file = log_path(row["eval_log_filename"])
    if not eval_file.exists():
        raise SystemExit(
            f"missing {eval_file}. Run: uv run python scripts/extract_slice_logs.py"
        )

    from inspect_ai.log import read_eval_log, read_eval_log_sample

    header = read_eval_log(eval_file, header_only=True)
    sample = read_eval_log_sample(eval_file, uuid=row["sample_uuid"])
    ev = header.eval
    messages = list(getattr(sample, "messages", None) or [])
    events = list(getattr(sample, "events", None) or [])
    scores = getattr(sample, "scores", None) or {}
    roles = Counter(getattr(msg, "role", "?") for msg in messages)
    calls, call_source = collect_tool_calls(sample)
    event_kinds = Counter(
        str(getattr(event, "event", None) or getattr(event, "type", None) or "?")
        for event in events
    )

    banner(
        "Inspect anatomy    (attack-agent eval, not a monitor eval)",
        f"{row['slot']}    uuid {row['sample_uuid']}",
        str(eval_file),
    )

    section("EvalLog.eval    (the run)")
    table(
        ("field", "value"),
        [
            ("eval_id", attr(ev, "eval_id")),
            ("task", attr(ev, "task")),
            ("model", attr(ev, "model")),
            ("solver", attr(ev, "solver")),
            ("dataset", attr(getattr(ev, "dataset", None), "name")),
            ("created", attr(ev, "created")),
        ],
        right=(),
    )
    note(
        "task/solver here describe the attacking coding agent. "
        "A monitor eval (chunks 10+) will have task names like ft_monitor "
        "or debate_monitor, and its solver will be generate() or assigned_debate()."
    )

    section("Sample    (one trajectory)")
    table(
        ("field", "value"),
        [
            ("id", attr(sample, "id")),
            ("uuid", attr(sample, "uuid")),
            ("matches slice uuid", "yes" if attr(sample, "uuid") == row["sample_uuid"] else "no"),
            ("messages", str(len(messages))),
            ("events", str(len(events))),
            ("tool calls", f"{len(calls)} from {call_source}"),
            ("scores", str(len(scores))),
        ],
        right=(),
    )

    section("messages    (chat history; tool_calls hang off assistant turns)")
    if roles:
        table(("role", "n"), [(role, n) for role, n in roles.most_common()])
    else:
        item_list(("no messages",))
    note(
        "Full-trajectory monitoring uses tool_calls on assistant messages "
        "(or tool events), not the tool outputs. That list is what later "
        "Samples put in {tool_calls}."
    )

    section("events    (Inspect's finer timeline)")
    if event_kinds:
        table(
            ("event", "n"),
            sorted(event_kinds.items(), key=lambda item: (-item[1], item[0])),
        )
    else:
        item_list(("no events",))

    section("scores    (this log's scorers, not our monitor Task)")
    names = sorted(scores)
    programmatic = [n for n in names if n in {"main_task_success", "side_task_success"}]
    other = [n for n in names if n not in programmatic]
    table(
        ("kind", "names"),
        [
            ("BashArena tests", ", ".join(programmatic) or "—"),
            ("in-log monitors / other", ", ".join(other) or "—"),
        ],
        right=(),
    )
    note(
        "main_task_success / side_task_success are environment tests. "
        "They are not the ControlArena 0–10 FT monitor. Stored FT scores "
        "live in master.parquet (scripts/catch_rates.py)."
    )

    section("Glossary for later chunks")
    item_list(
        (
            "Sample — one trajectory we will re-score",
            "Task — dataset + solver + scorer (evals/ft_monitor.py, evals/debate_monitor.py)",
            "Solver — how the model is called (generate once, or 3-call debate)",
            "Scorer — parse <score> from the last completion",
            "Eval log — Inspect writes a new .eval under logs/ when we run a Task",
        )
    )


if __name__ == "__main__":
    main()
