"""Plain-text tables and section headers for script stdout."""

from __future__ import annotations

import textwrap
from collections.abc import Iterable, Sequence

WIDTH = 88
INDENT = "  "
BAR_WIDTH = 24


def banner(title: str, *details: str) -> None:
    print(title)
    for line in details:
        print(line)


def section(title: str) -> None:
    print()
    print(title)
    print("-" * min(WIDTH, max(36, len(title))))


def subsection(title: str) -> None:
    print()
    print(f"{INDENT}{title}")


def note(text: str) -> None:
    print()
    for line in textwrap.wrap(text, width=WIDTH - len(INDENT)):
        print(f"{INDENT}{line}")


def bar(fraction: float, *, width: int = BAR_WIDTH) -> str:
    clamped = max(0.0, min(1.0, fraction))
    filled = int(round(clamped * width))
    return "█" * filled + "░" * (width - filled)


def _cell(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _is_numeric_column(cells: Sequence[str]) -> bool:
    if not cells:
        return False
    for cell in cells:
        if cell in {"", "—", "-"}:
            continue
        stripped = cell.replace(",", "").replace("%", "").lstrip("±")
        try:
            float(stripped)
        except ValueError:
            return False
    return True


def table(
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
    *,
    right: Sequence[int] | None = None,
    footer: int = 0,
) -> None:
    str_rows = [[_cell(c) for c in row] for row in rows]
    cols = len(headers)
    for row in str_rows:
        if len(row) != cols:
            raise ValueError(f"row has {len(row)} cells, expected {cols}")

    widths = [len(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    if right is None:
        right_cols = {
            i
            for i in range(cols)
            if i > 0 and _is_numeric_column([row[i] for row in str_rows])
        }
    else:
        right_cols = set(right)

    def fmt_row(cells: Sequence[str]) -> str:
        parts: list[str] = []
        for i, cell in enumerate(cells):
            aligned = cell.rjust(widths[i]) if i in right_cols else cell.ljust(widths[i])
            parts.append(aligned)
        return "  ".join(parts)

    def rule() -> str:
        return "  ".join("-" * w for w in widths)

    print(INDENT + fmt_row(list(headers)))
    print(INDENT + rule())
    body_end = len(str_rows) - footer if footer else len(str_rows)
    for row in str_rows[:body_end]:
        print(INDENT + fmt_row(row))
    if footer:
        print(INDENT + rule())
        for row in str_rows[body_end:]:
            print(INDENT + fmt_row(row))


def counts_table(
    labels: Sequence[str],
    counts: Sequence[int],
    *,
    percent_of: int | None = None,
    label_header: str = "",
    show_total: bool = True,
    show_bar: bool = True,
) -> None:
    denom = percent_of if percent_of is not None else sum(counts)
    rows: list[tuple[str, str, str] | tuple[str, str, str, str]] = []
    for label, count in zip(labels, counts, strict=True):
        frac = count / denom if denom else 0.0
        pct = f"{100 * frac:.1f}%" if denom else "—"
        if show_bar:
            rows.append((label, f"{count:,}", pct, bar(frac)))
        else:
            rows.append((label, f"{count:,}", pct))
    if show_total:
        total = sum(counts)
        total_pct = "100.0%" if percent_of is None else "—"
        if show_bar:
            rows.append(("total", f"{total:,}", total_pct, ""))
        else:
            rows.append(("total", f"{total:,}", total_pct))
    headers: tuple[str, ...]
    if show_bar:
        headers = (label_header or "label", "n", "%", "")
    else:
        headers = (label_header or "label", "n", "%")
    table(headers, rows, footer=1 if show_total else 0)


def wrap_field(label: str, value: object, *, width: int = 72) -> None:
    text = _cell(value) if value is not None else ""
    print(f"{INDENT}{label}")
    if not text:
        print(f"{INDENT * 2}—")
        return
    for line in textwrap.wrap(text, width=width):
        print(f"{INDENT * 2}{line}")


def item_list(items: Sequence[str]) -> None:
    if not items:
        print(f"{INDENT}—")
        return
    for item in items:
        print(f"{INDENT}{item}")
