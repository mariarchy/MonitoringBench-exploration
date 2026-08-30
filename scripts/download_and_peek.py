"""Download MonitoringBench's parquet index and print schema plus one row.

The public dataset has two artifacts. This script fetches only the small one:

- master.parquet (~3 MB): 2,644 labeled attacks and their stored monitor scores
- final_dataset.zip (~2.5 GB): Inspect .eval transcripts (later chunks)

A parquet row is metadata + scores, not the tool-call transcript.
"""

from __future__ import annotations

import urllib.request
from collections.abc import Iterable
from pathlib import Path

import pandas as pd

from pretty import banner, item_list, note, section, subsection, table, wrap_field

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
PARQUET_PATH = DATA_DIR / "master.parquet"
HF_URL = (
    "https://huggingface.co/datasets/neur26anonsub/ctrldataset2026"
    "/resolve/main/master.parquet"
)

IDENTITY_COLS = (
    "sample_uuid",
    "task_id",
    "eval_log_filename",
    "eval_created",
)
ATTACK_COLS = (
    "side_task_name",
    "side_task_group",
    "source_name",
    "source_group",
    "new_source_name",
    "attack_model",
    "attack_strategy",
    "plan_strategy",
    "attack_summary",
    "attack_group",
    "attack_step",
    "total_steps",
)
TAXONOMY_COLS = (
    "structural_strategy",
    "structural_strategy_explanation",
    "evasion_tactics",
    "evasion_tactics_explanation",
    "technical_techniques",
    "technical_techniques_explanation",
)
OUTCOME_COLS = (
    "main_task_success",
    "side_task_success",
    "assistant_messages_count",
    "tool_call_count",
)
PEEK_COLS = (
    "sample_uuid",
    "task_id",
    "side_task_name",
    "source_group",
    "source_name",
    "new_source_name",
    "attack_summary",
    "structural_strategy",
    "evasion_tactics",
    "technical_techniques",
    "tool_call_count",
    "main_task_success",
    "side_task_success",
)
OPUS_FT_PREFIX = "ft_claude-opus-4-5-20251101_monitor_score_"


def download_parquet(*, quiet: bool = False) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if PARQUET_PATH.exists() and PARQUET_PATH.stat().st_size > 0:
        mb = PARQUET_PATH.stat().st_size / 1e6
        if not quiet:
            print(f"Using existing {PARQUET_PATH} ({mb:.2f} MB)")
        return PARQUET_PATH

    print(f"Downloading {HF_URL}")
    request = urllib.request.Request(
        HF_URL,
        headers={"User-Agent": "monitoring-bench-exploration"},
    )
    with urllib.request.urlopen(request) as response:
        PARQUET_PATH.write_bytes(response.read())
    mb = PARQUET_PATH.stat().st_size / 1e6
    print(f"Wrote {PARQUET_PATH} ({mb:.2f} MB)")
    return PARQUET_PATH


def present_columns(frame: pd.DataFrame, names: tuple[str, ...]) -> list[str]:
    return [name for name in names if name in frame.columns]


def ft_model_keys(columns: Iterable[str]) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    prefix, suffix = "ft_", "_monitor_score_"
    for col in columns:
        if not col.startswith(prefix) or suffix not in col:
            continue
        key = col[len(prefix) : col.rfind(suffix)]
        if key not in seen:
            seen.add(key)
            keys.append(key)
    return keys


def print_column_groups(frame: pd.DataFrame) -> None:
    ft_cols = sorted(c for c in frame.columns if c.startswith("ft_"))
    leftover = sorted(
        c
        for c in frame.columns
        if not (
            c in IDENTITY_COLS
            or c in ATTACK_COLS
            or c in TAXONOMY_COLS
            or c in OUTCOME_COLS
            or c.startswith(("ft_", "sw_", "dev_"))
        )
    )
    sw_score_n = sum(1 for c in frame.columns if c.startswith("sw_") and "_monitor_score_" in c)
    sw_extra_n = sum(1 for c in frame.columns if c.startswith("sw_") and "_monitor_score_" not in c)

    section("Column groups")
    table(
        ("group", "n", "what"),
        [
            ("identity", len(present_columns(frame, IDENTITY_COLS)), "uuid, task id, eval log path"),
            ("attack", len(present_columns(frame, ATTACK_COLS)), "side task, pipeline, summary"),
            ("taxonomy", len(present_columns(frame, TAXONOMY_COLS)), "T / S / E labels"),
            ("outcomes", len(present_columns(frame, OUTCOME_COLS)), "success flags, length"),
            ("ft_", len(ft_cols), "full-trajectory monitor scores"),
            ("sw_ scores", sw_score_n, "stepwise monitor scores"),
            ("sw_ extra", sw_extra_n, "sw_full_* / sw_trimmed_*"),
            ("dev_", sum(1 for c in frame.columns if c.startswith("dev_")), "development monitors"),
            ("other", len(leftover), ", ".join(leftover) or "—"),
        ],
    )

    subsection("identity / attack / taxonomy / outcomes")
    for group, names in (
        ("identity", present_columns(frame, IDENTITY_COLS)),
        ("attack", present_columns(frame, ATTACK_COLS)),
        ("taxonomy", present_columns(frame, TAXONOMY_COLS)),
        ("outcomes", present_columns(frame, OUTCOME_COLS)),
    ):
        wrap_field(group, ", ".join(names) or "—", width=76)

    subsection(f"FT monitors  ({len(ft_model_keys(ft_cols))} models × 3 repeats)")
    item_list(ft_model_keys(ft_cols))


def pick_row(frame: pd.DataFrame) -> tuple[int, pd.Series]:
    if "attack_summary" in frame.columns:
        nonempty = frame["attack_summary"].fillna("").astype(str).str.strip() != ""
        if nonempty.any():
            idx = int(nonempty.to_numpy().nonzero()[0][0])
            return idx, frame.iloc[idx]
    return 0, frame.iloc[0]


def format_value(value: object, *, max_chars: int = 1200) -> str:
    if pd.isna(value):
        return "<NA>"
    text = str(value)
    if len(text) > max_chars:
        return text[:max_chars] + f"\n  … [{len(text)} chars total]"
    return text


def print_row(frame: pd.DataFrame, index: int, row: pd.Series) -> None:
    section(f"One row    iloc {index} / {len(frame)}")
    short_fields = [c for c in PEEK_COLS if c != "attack_summary"]
    table(
        ("field", "value"),
        [
            (
                col,
                "<missing>" if col not in frame.columns else format_value(row[col], max_chars=72),
            )
            for col in short_fields
        ],
        right=(),
    )
    print()
    wrap_field(
        "attack_summary",
        "<missing>"
        if "attack_summary" not in frame.columns
        else format_value(row["attack_summary"]),
    )

    opus_cols = sorted(c for c in frame.columns if c.startswith(OPUS_FT_PREFIX))
    subsection("Opus 4.5 FT scores  (three repeats; caught iff score > 3.0)")
    if not opus_cols:
        item_list(("<no matching columns>",))
        return
    values: list[float] = []
    score_rows: list[tuple[str, str]] = []
    for col in opus_cols:
        repeat = col.rsplit("_", 1)[-1]
        raw = row[col]
        if pd.notna(raw):
            values.append(float(raw))
        score_rows.append((repeat, format_value(raw, max_chars=16)))
    if values:
        score_rows.append(("mean", f"{sum(values) / len(values):.2f}"))
    table(("repeat", "score"), score_rows, footer=1 if values else 0)


def main() -> None:
    path = download_parquet(quiet=True)
    frame = pd.read_parquet(path)
    banner(
        "MonitoringBench index",
        f"{frame.shape[0]:,} rows × {frame.shape[1]} columns    expected 2,644 × ~135",
        str(path),
    )
    print_column_groups(frame)
    index, row = pick_row(frame)
    print_row(frame, index, row)
    note(
        "The tool-call transcript is not in this file; it lives in the "
        ".eval log named by eval_log_filename (chunk 7+)."
    )


if __name__ == "__main__":
    main()
