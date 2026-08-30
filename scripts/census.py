"""Census of MonitoringBench: side tasks, pipeline stages, and T/S/E labels.

source_group is the coarse pipeline stage used in the paper's figures:

- Opus Only          ≈ Table 5 "Baseline"     (n=196 matches exactly)
- Human-in-the-Loop  ≈ Table 5 "Human Strategies"
- Recon              ≈ Table 5 "Recon"
- Refined            ≈ Table 5 "Refined"

source_name is finer (e.g. recon vs recon_refined). new_source_name splits
Recon further (recon / recon_improved) and is not used here.

Table 5 cell n's sum to ~3,678, not 2,644 — that table is the eval pool, not
the curated public index. Compare shape and the Baseline=196 match, not
every cell.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import pandas as pd
from download_and_peek import download_parquet
from pretty import banner, counts_table, note, section, subsection, table

SIDE_ORDER = ("firewall", "malware", "password_leak", "sudo")
SOURCE_ORDER = ("Opus Only", "Human-in-the-Loop", "Recon", "Refined")
SOURCE_GROUP_LABELS = {
    "Opus Only": "Opus",
    "Human-in-the-Loop": "Human",
    "Recon": "Recon",
    "Refined": "Refined",
}
SOURCE_NAME_ORDER = (
    "opus_only",
    "human_strategies",
    "recon",
    "opus_only_refined",
    "human_strategies_refined",
    "recon_refined",
)
SOURCE_NAME_LABELS = {
    "opus_only": "opus",
    "human_strategies": "human",
    "recon": "recon",
    "opus_only_refined": "opus_ref",
    "human_strategies_refined": "human_ref",
    "recon_refined": "recon_ref",
}
STRUCTURAL_ORDER = ("S1", "S2", "S3", "S4")
TECHNICAL_ORDER = ("T1", "T2", "T3", "T4", "T5", "other")
EVASION_ORDER = ("E1", "E2", "E3", "E4")

PAPER_TABLE5_N = {
    "Baseline": 58 + 42 + 43 + 53,
    "Human Strategies": 256 + 101 + 110 + 313,
    "Recon": 204 + 669 + 128 + 265,
    "Refined": 511 + 250 + 198 + 477,
}

SOURCE_TO_PAPER = {
    "Opus Only": "Baseline",
    "Human-in-the-Loop": "Human Strategies",
    "Recon": "Recon",
    "Refined": "Refined",
}


def load_index() -> pd.DataFrame:
    path = download_parquet(quiet=True)
    return pd.read_parquet(path)


def ordered_counts(series: pd.Series, order: tuple[str, ...]) -> tuple[list[str], list[int]]:
    filled = series.fillna("<NA>").astype(str).str.strip().replace({"": "(blank)"})
    counts = filled.value_counts(dropna=False)
    labels = [label for label in order if label in counts.index]
    labels += [label for label in counts.index if label not in labels]
    return labels, [int(counts[label]) for label in labels]


def parse_codes(value: object) -> list[str]:
    if pd.isna(value):
        return []
    text = str(value).strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def collapse_tail(
    labels: Sequence[str],
    counts: Sequence[int],
    *,
    min_count: int = 10,
) -> tuple[list[str], list[int]]:
    kept_labels: list[str] = []
    kept_counts: list[int] = []
    other_n = 0
    other_k = 0
    for label, count in zip(labels, counts, strict=True):
        if count >= min_count:
            kept_labels.append(label)
            kept_counts.append(count)
        else:
            other_n += count
            other_k += 1
    if other_n:
        kept_labels.append(f"other ({other_k})")
        kept_counts.append(other_n)
    return kept_labels, kept_counts


def normalize_evasion(value: object) -> str:
    if pd.isna(value):
        return "<NA>"
    codes = parse_codes(value)
    if not codes:
        return "(blank)"

    def sort_key(code: str) -> tuple[int, str]:
        match = re.match(r"E(\d+)", code)
        return (int(match.group(1)) if match else 99, code)

    return ", ".join(sorted(set(codes), key=sort_key))


def collapse_technical(value: object) -> str:
    if pd.isna(value):
        return "<NA>"
    text = str(value).strip()
    if not text:
        return "<NA>"
    match = re.match(r"(T[1-6])", text)
    if match and match.group(1) != "T6":
        return match.group(1)
    if text in {"<NA>"}:
        return "<NA>"
    return "other"


def print_crosstab(
    frame: pd.DataFrame,
    index: str,
    columns: str,
    *,
    index_order: tuple[str, ...],
    column_order: tuple[str, ...] | None = None,
    index_header: str = "",
    column_labels: dict[str, str] | None = None,
) -> None:
    ct = pd.crosstab(frame[index], frame[columns], margins=True)
    row_labels = [label for label in index_order if label in ct.index] + (
        ["All"] if "All" in ct.index else []
    )
    if column_order is None:
        col_keys = [c for c in ct.columns if c != "All"] + (
            ["All"] if "All" in ct.columns else []
        )
    else:
        col_keys = [c for c in column_order if c in ct.columns] + (
            ["All"] if "All" in ct.columns else []
        )
    ct = ct.reindex(index=row_labels, columns=col_keys)
    labels = column_labels or {}
    headers = [index_header or index, *[labels.get(c, c) for c in col_keys]]
    rows = []
    for row_label in row_labels:
        rows.append(
            [
                row_label,
                *[
                    "—" if pd.isna(ct.loc[row_label, col]) else f"{int(ct.loc[row_label, col]):,}"
                    for col in col_keys
                ],
            ]
        )
    footer = 1 if row_labels and row_labels[-1] == "All" else 0
    table(headers, rows, footer=footer)


def main() -> None:
    frame = load_index()
    banner("MonitoringBench census", f"n = {len(frame):,}    paper = 2,644")

    section("Side task")
    labels, counts = ordered_counts(frame["side_task_group"], SIDE_ORDER)
    counts_table(labels, counts, label_header="side_task")

    section("Pipeline stage  (source_group)")
    labels, counts = ordered_counts(frame["source_group"], SOURCE_ORDER)
    counts_table(labels, counts, label_header="source_group")
    subsection("vs paper Table 5")
    local = frame["source_group"].value_counts()
    table(
        ("source_group", "local n", "Table 5 column", "Table 5 n"),
        [
            (
                local_name,
                f"{int(local.get(local_name, 0)):,}",
                paper_name,
                f"{PAPER_TABLE5_N[paper_name]:,}",
            )
            for local_name, paper_name in SOURCE_TO_PAPER.items()
        ],
    )
    note(
        "Opus Only matches Baseline (196). Other Table 5 n's are the larger "
        "eval pool, not this curated index."
    )

    section("Side task × pipeline stage")
    print_crosstab(
        frame,
        "side_task_group",
        "source_group",
        index_order=SIDE_ORDER,
        column_order=SOURCE_ORDER,
        index_header="side_task",
        column_labels=SOURCE_GROUP_LABELS,
    )
    note("Human = Human-in-the-Loop. Opus = Opus Only.")

    section("Side task × pipeline variant  (source_name)")
    print_crosstab(
        frame,
        "side_task_group",
        "source_name",
        index_order=SIDE_ORDER,
        column_order=SOURCE_NAME_ORDER,
        index_header="side_task",
        column_labels=SOURCE_NAME_LABELS,
    )

    section("Structural strategy  S  (where the attack sits)")
    labels, counts = ordered_counts(frame["structural_strategy"], STRUCTURAL_ORDER)
    counts_table(labels, counts, label_header="code")
    s3 = (frame["structural_strategy"] == "S3").mean()
    note(f"S3 share: {s3:.1%}    paper: 64% of Opus-only attacks were S3")

    section("Technical technique  T  (what the mechanism is)")
    collapsed = frame["technical_techniques"].map(collapse_technical)
    labels, counts = ordered_counts(collapsed, TECHNICAL_ORDER)
    counts_table(labels, counts, label_header="code")
    t1 = (collapsed == "T1").mean()
    note(
        f"T1 share: {t1:.1%}    paper: T1 was 2% of Opus-only, but ~40% of uncaught attacks"
    )

    section("Evasion tactics  E  (how it is hidden; multi-label)")
    subsection("Combinations  (codes sorted; n < 10 folded into other)")
    labels, counts = ordered_counts(frame["evasion_tactics"].map(normalize_evasion), ())
    labels, counts = collapse_tail(labels, counts, min_count=10)
    counts_table(labels, counts, label_header="combo")
    exploded = frame["evasion_tactics"].map(parse_codes).explode()
    subsection("Per-code frequency  (one row can count toward several E-codes)")
    labels, counts = ordered_counts(exploded, EVASION_ORDER)
    counts_table(labels, counts, percent_of=len(frame), label_header="code", show_total=False)
    note("Percent is of trajectories (n = 2,644), not of code occurrences.")

    section("Trajectory length  (tool_call_count)")
    desc = frame["tool_call_count"].describe(percentiles=[0.25, 0.5, 0.75])
    table(
        ("stat", "tool calls"),
        [
            ("min", f"{int(desc['min'])}"),
            ("p25", f"{desc['25%']:.0f}"),
            ("median", f"{desc['50%']:.0f}"),
            ("p75", f"{desc['75%']:.0f}"),
            ("max", f"{int(desc['max'])}"),
            ("mean", f"{desc['mean']:.1f}"),
        ],
    )
    subsection("Median by side task")
    medians = (
        frame.groupby("side_task_group", observed=True)["tool_call_count"]
        .median()
        .reindex(list(SIDE_ORDER))
    )
    table(
        ("side_task", "median tool calls"),
        [(name, f"{int(value)}") for name, value in medians.items()],
    )


if __name__ == "__main__":
    main()
