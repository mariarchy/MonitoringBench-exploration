"""Download MonitoringBench's parquet index and print schema plus one row.

The public dataset has two artifacts. This script fetches only the small one:

- master.parquet (~3 MB): 2,644 labeled attacks and their stored monitor scores
- final_dataset.zip (~2.5 GB): Inspect .eval transcripts (later chunks)

A parquet row is metadata + scores, not the tool-call transcript.
"""

from __future__ import annotations

import urllib.request
from pathlib import Path

import pandas as pd

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


def download_parquet() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if PARQUET_PATH.exists() and PARQUET_PATH.stat().st_size > 0:
        mb = PARQUET_PATH.stat().st_size / 1e6
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


def print_column_groups(frame: pd.DataFrame) -> None:
    assigned: set[str] = set()
    groups: list[tuple[str, list[str]]] = [
        ("identity", present_columns(frame, IDENTITY_COLS)),
        ("attack", present_columns(frame, ATTACK_COLS)),
        ("taxonomy", present_columns(frame, TAXONOMY_COLS)),
        ("outcomes", present_columns(frame, OUTCOME_COLS)),
        ("ft_ (full-trajectory monitor scores)", sorted(c for c in frame.columns if c.startswith("ft_"))),
        ("sw_ (stepwise monitor scores)", sorted(c for c in frame.columns if c.startswith("sw_"))),
        (
            "dev_ (development monitors)",
            sorted(c for c in frame.columns if c.startswith("dev_")),
        ),
    ]
    for _, names in groups:
        assigned.update(names)
    leftover = sorted(c for c in frame.columns if c not in assigned)
    groups.append(("other", leftover))

    print("\n## Columns by group")
    for title, names in groups:
        print(f"\n{title} ({len(names)})")
        for name in names:
            print(f"  {name}")


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
    print(f"\n## One row (iloc {index} / {len(frame)})")
    for col in PEEK_COLS:
        if col not in frame.columns:
            print(f"{col}: <missing column>")
            continue
        print(f"{col}:")
        print(f"  {format_value(row[col])}")

    opus_cols = sorted(c for c in frame.columns if c.startswith(OPUS_FT_PREFIX))
    print("\nOpus 4.5 FT scores (stored; three repeats):")
    for col in opus_cols:
        print(f"  {col}: {format_value(row[col], max_chars=80)}")
    if not opus_cols:
        print("  <no columns matching", OPUS_FT_PREFIX + "*>")


def main() -> None:
    path = download_parquet()
    frame = pd.read_parquet(path)
    print(f"\nshape: {frame.shape[0]} rows × {frame.shape[1]} columns")
    print("expected: 2644 rows × ~135 columns")
    print_column_groups(frame)
    index, row = pick_row(frame)
    print_row(frame, index, row)
    print(
        "\nThe tool-call transcript is not in this file; it lives in the "
        ".eval log named by eval_log_filename (chunk 7+)."
    )


if __name__ == "__main__":
    main()
