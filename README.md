# MonitoringBench exploration

A local, chunk-by-chunk walkthrough of [MonitoringBench](https://arxiv.org/abs/2605.09684): the 2,644 BashArena attack trajectories, the full-trajectory (FT) monitor prompt, and where monitors fail.

**FT (full trajectory)** means the monitor scores the finished episode once — the sequence of tool calls, without tool outputs — and returns a single 0–10 suspiciousness score. That is what this pilot re-runs. Stepwise (SW) monitoring is out of scope.

This repo is for reading and re-scoring **frozen** trajectories. It does not regenerate the attack pipeline.

## Layout

| Path | Role |
| --- | --- |
| `prompts/` | Monitor prompt (chunk 2) |
| `thresholds.json` | Paper 1% FPR thresholds (chunk 2) |
| `scripts/` | One numbered script per later chunk |
| `data/` | Gitignored downloads (parquet, inspect logs) |
| `slices/` | Frozen 12-trajectory IDs (chunk 6) |
| `notes/` | Transcript dumps and failure-mode writeups |

## Chunks

Work one chunk, read the output, then continue. No API key until chunk 10.

| # | Goal | Command |
| --- | --- | --- |
| 1 | Empty project | `uv run python -c "import pandas, pyarrow"` |
| 2 | Pin monitor prompt + thresholds | *(files only)* |
| 3 | Download parquet; print one row | `uv run python scripts/03_download_and_peek.py` |
| 4 | Census: side task × pipeline, T/S/E | `uv run python scripts/04_census.py` |
| 5 | Catch rates from stored FT scores | `uv run python scripts/05_catch_rates.py` |
| 6 | Freeze 12 UUIDs | `uv run python scripts/06_select_slice.py` |
| 7 | Extract inspect logs for those 12 | `uv run python scripts/07_extract_slice_logs.py` |
| 8 | Read one transcript | `uv run python scripts/08_read_one.py` |
| 9 | Format the FT monitor prompt (no API) | `uv run python scripts/09_format_monitor_prompt.py` |
| 10 | Live Opus 4.5 FT score on 1 trajectory | `uv run python scripts/10_score_one.py` |
| 11 | Score the other 11; compare to parquet | `uv run python scripts/11_score_slice.py` |
| 12 | Hand-label uncaught rows A/B/C/D | *(notes)* |

## Run this next

You are at **chunk 1**. Confirm the environment:

```bash
uv sync
uv run python -c "import pandas, pyarrow; print('ok', pandas.__version__)"
```

Then chunk 2: copy the ControlArena default monitor prompt and Appendix L thresholds into the repo as readable files. No data download yet.
