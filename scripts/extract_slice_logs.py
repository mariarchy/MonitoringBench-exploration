"""Download final_dataset.zip and extract only the 12 slice Inspect logs.

Parquet is an index. Tool-call transcripts live in Inspect .eval files inside
a ~2.47 GB zip, grouped by side task (firewall/, malware/, password_leak/,
sudo/). Join key: sample_uuid ↔ Inspect sample uuid.

Does not unzip the whole archive into the working tree.
"""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

from huggingface_hub import hf_hub_download
from pretty import banner, note, section, table

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
SLICE_PATH = REPO_ROOT / "slices" / "pilot_v1.json"
ZIP_PATH = DATA_DIR / "final_dataset.zip"
LOGS_DIR = DATA_DIR / "logs"
ZIP_URL = (
    "https://huggingface.co/datasets/neur26anonsub/ctrldataset2026"
    "/resolve/main/final_dataset.zip"
)
# Hugging Face file listing (May 2026). Used when HEAD has no Content-Length.
EXPECTED_ZIP_BYTES = 2_465_179_333
CHUNK_BYTES = 1024 * 1024
USER_AGENT = "monitoring-bench-exploration"


def load_slice(path: Path = SLICE_PATH) -> dict:
    if not path.exists():
        raise FileNotFoundError(
            f"missing slice file {path} — run scripts/select_slice.py first"
        )
    return json.loads(path.read_text())


def wanted_filenames(slice_data: dict) -> dict[str, dict]:
    """Map eval log basename → first slice row that names it."""
    wanted: dict[str, dict] = {}
    for row in slice_data["trajectories"]:
        name = Path(row["eval_log_filename"]).name
        wanted.setdefault(name, row)
    return wanted


def log_path(filename: str, *, logs_dir: Path = LOGS_DIR) -> Path:
    return logs_dir / Path(filename).name


def member_basename(name: str) -> str:
    # Split the filename on the last slash and return the filename
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def skip_member(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    # Ignore the __MACOSX folder
    if "__MACOSX" in parts:
        return True
    base = parts[-1]
    return not base or base.startswith(("._", "."))


def find_members(
    zf: zipfile.ZipFile, wanted: dict[str, dict]
) -> tuple[dict[str, zipfile.ZipInfo], int]:
    found: dict[str, zipfile.ZipInfo] = {}
    eval_n = 0
    for info in zf.infolist():
        name = info.filename
        if skip_member(name) or info.is_dir():
            continue
        if name.replace("\\", "/").lower().endswith(".eval"):
            eval_n += 1
        base = member_basename(name)
        if base in wanted and base not in found:
            found[base] = info
    return found, eval_n


def extract_one(zf: zipfile.ZipFile, info: zipfile.ZipInfo, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if (
        dest.exists()
        and dest.stat().st_size == info.file_size
        and dest.stat().st_size > 0
    ):
        return
    tmp = dest.with_suffix(dest.suffix + ".partial")
    with zf.open(info) as src, tmp.open("wb") as out:
        shutil.copyfileobj(src, out, length=CHUNK_BYTES)
    tmp.replace(dest)


def extract_slice(
    zf: zipfile.ZipFile, slice_data: dict
) -> list[tuple[dict, zipfile.ZipInfo, Path]]:
    wanted = wanted_filenames(slice_data)
    found, eval_n = find_members(zf, wanted)
    missing = sorted(set(wanted) - set(found))
    section("Zip contents")
    table(
        ("", "n"),
        [
            (".eval files in zip", f"{eval_n:,}"),
            ("needed by slice", f"{len(wanted):,}"),
            ("matched by basename", f"{len(found):,}"),
            ("missing", f"{len(missing):,}"),
        ],
    )
    if missing:
        raise FileNotFoundError(
            "slice eval logs not in zip:\n  " + "\n  ".join(missing)
        )

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    extracted: list[tuple[dict, zipfile.ZipInfo, Path]] = []
    for filename, row in wanted.items():
        info = found[filename]
        dest = log_path(filename)
        extract_one(zf, info, dest)
        extracted.append((row, info, dest))
    return extracted


def print_extracted(rows: list[tuple[dict, zipfile.ZipInfo, Path]]) -> None:
    section("Extracted into data/logs/")
    table(
        ("slot", "side", "mb", "zip member"),
        [
            (
                row["slot"],
                row["side_task_group"],
                f"{dest.stat().st_size / 1e6:.2f}",
                info.filename.replace("\\", "/"),
            )
            for row, info, dest in rows
        ],
    )
    leftover = sorted(
        p.name
        for p in LOGS_DIR.glob("*.eval")
        if p.name not in {row["eval_log_filename"] for row, _info, _dest in rows}
    )
    if leftover:
        note("Other .eval files already in data/logs/: " + ", ".join(leftover))


def main() -> None:
    slice_data = load_slice()
    n = len(slice_data["trajectories"])
    banner(
        "Extract slice logs",
        f"{n} trajectories from {SLICE_PATH.name}",
        "parquet indexes; .eval files hold the transcripts",
    )
    zip_path = hf_hub_download(
        repo_id="neur26anonsub/ctrldataset2026",
        filename="final_dataset.zip",
        repo_type="dataset",
    )
    with zipfile.ZipFile(zip_path) as zf:
        rows = extract_slice(zf, slice_data)
    print_extracted(rows)
    on_disk = list(LOGS_DIR.glob("*.eval"))
    note(
        f"{len(on_disk)} .eval file(s) in {LOGS_DIR} — not the full archive. "
        "Join each slice sample_uuid to the Inspect sample uuid inside its log "
        "(chunk 8: scripts/read_one.py)."
    )


if __name__ == "__main__":
    main()
