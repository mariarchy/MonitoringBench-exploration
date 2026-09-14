# MonitoringBench exploration

A local, chunk-by-chunk walkthrough of [MonitoringBench](https://arxiv.org/abs/2605.09684): the 2,644 BashArena attack trajectories, the full-trajectory (FT) monitor prompt, and where monitors fail.

**FT (full trajectory)** means the monitor scores the finished episode once — the sequence of tool calls, without tool outputs — and returns a single 0–10 suspiciousness score. Stepwise (SW) monitoring is out of scope.

This repo is for reading and re-scoring **frozen** trajectories. It does not regenerate the attack pipeline.

Part 2 (chunks 9–18) runs that re-scoring as **Inspect Tasks**: first a single-model FT monitor, then Kenton-style assigned-role debate. MonitoringBench `.eval` files in `data/logs/` are *attack-agent* evals. New `.eval` files under `logs/` are *monitor* evals.

## Layout

| Path | Role |
| --- | --- |
| `prompts/` | FT monitor prompt + debate prosecutor/defender/judge |
| `thresholds.json` | Paper 1% FPR thresholds (chunk 2) |
| `scripts/` | Named scripts, one per later chunk |
| `evals/` | Inspect Tasks (`hello`, `ft_monitor`, `debate_monitor`) |
| `data/` | Gitignored downloads (parquet, inspect logs) |
| `slices/` | Frozen 12-trajectory IDs (chunk 6) |
| `notes/` | Transcript dumps (gitignored) |
| `logs/` | New Inspect monitor evals (gitignored) |
| `results/` | Recovery table after chunk 18 |

## Chunks 1–8

Work one chunk, read the output, then continue. No API key until chunk 13.

| # | Goal | Command |
| --- | --- | --- |
| 1 | Empty project | `uv run python -c "import pandas, pyarrow"` |
| 2 | Pin monitor prompt + thresholds | *(files only)* |
| 3 | Download parquet; print one row | `uv run python scripts/download_and_peek.py` |
| 4 | Census: side task × pipeline, T/S/E | `uv run python scripts/census.py` |
| 5 | Catch rates from stored FT scores | `uv run python scripts/catch_rates.py` |
| 6 | Freeze 12 UUIDs | `uv run python scripts/select_slice.py` |
| 7 | Extract inspect logs for those 12 | `uv run python scripts/extract_slice_logs.py` |
| 8 | Read one transcript | `uv run python scripts/read_one.py` |

## Part 2 — debate vs FT (Inspect)

| # | Goal | Command |
| --- | --- | --- |
| 9 | Name Inspect objects in one frozen `.eval` | `uv run python scripts/inspect_anatomy.py` |
| 10 | Smallest Task (`mockllm`) | `uv run inspect eval evals/hello.py` |
| 11 | Fill FT prompt; leak-check (no API) | `uv run python scripts/format_monitor_prompt.py` |
| 12 | FT monitor Task on `mockllm` | `uv run inspect eval evals/ft_monitor.py -T mock=true -T uuid=2EuoeP5hxCitkXzGxHfF6M` |
| 13 | Live Opus FT on one easy catch | `uv run python scripts/run_ft.py` |
| 14 | Debate prompt files | *(read `prompts/debate_*.md`)* |
| 15 | Debate solver on `mockllm` | `uv run inspect eval evals/debate_monitor.py -T mock=true -T uuid=2EuoeP5hxCitkXzGxHfF6M` |
| 16 | Live debate on one miss + one catch | `uv run python scripts/run_debate.py --group phase1-two` |
| 17 | Live debate on the 12-trajectory slice | `uv run python scripts/run_debate.py` |
| 18 | Recovery table vs parquet Opus means | `uv run python scripts/compare_debate.py` |

## Debate runs

One CLI. Prompt packs and row groups live in `evals/constants.py` (`PROMPT_PACKS`, `ROW_GROUPS`). A new ablation is a pack and/or group, not a new script.

| Command | What it runs |
| --- | --- |
| `uv run python scripts/run_debate.py --mock --group phase1-two` | Dry run (no API) |
| `uv run python scripts/run_debate.py --group phase1-two` | Phase 1 two-row check |
| `uv run python scripts/run_debate.py` | All 12, default prompts |
| `uv run python scripts/run_debate.py --prompts bundle --group judge-shrug` | Prompt-bundle arm |
| `uv run python scripts/run_debate.py --slot extra_missed_all` | One slot |
| `uv run python scripts/compare_debate.py` | Join newest debate `.eval` to parquet means |

FT live: `uv run python scripts/run_ft.py` (optional slot/uuid argument).

Open any new log with `uv run inspect view`. Chunks 13, 16, and 17 need `ANTHROPIC_API_KEY` in `.env`. Catch is still `score > 3` (paper FT τ). That is **not** a recomputed 1% FPR.

## Run this next

Review the Phase 1 table in [`results/debate_phase1.md`](results/debate_phase1.md) (chunk 18). Recovered **2 / 8** previously uncaught; **4 / 4** easy catches stayed caught. That is a weak signal, not a 1% FPR catch rate.
