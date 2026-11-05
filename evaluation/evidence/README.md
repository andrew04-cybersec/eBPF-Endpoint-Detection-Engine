# Evaluation evidence

This folder holds the results behind the numbers in the paper (`article/ebpf-edr-flagship-short.md`): scores, reports, frozen-prediction comparisons, resource and `bpf_stats` summaries, derived tables, and checksums. It is a curated, privacy-reviewed subset of the files the evaluation harness wrote on the machine where the runs were made.

## What this folder is not

**The raw event data is not here and will not be available.** The original runs recorded every process execution on the test machine, including full command lines, paths and user names. That data (`events.jsonl`, `normalized.jsonl`, `alerts.jsonl`, `alerts.stamped.tsv`, the logs, about 700 MB) was reviewed for privacy, judged unsuitable to publish, and has been discarded.

Consequences, stated plainly:

- **The evaluation cannot be re-scored from these files.** `evaluation/evaluate.py` reads `alerts.stamped.tsv`, `events.jsonl` and the run folder; none of these are published. `scores.json` and `report.md` are the scorer's recorded outputs.
- **The numbers can be checked for consistency, not regenerated.** The derived files below (`alerts.summary.tsv`, `event_excerpts.tsv`, `event_counts.csv`, `file_open_summary.tsv`) let a reader recompute several headline figures, such as latency, but they were computed by the author from the raw data once, and the raw data is no longer available to check them against. `VERIFICATION.md` records what they were checked against at the time.
- **This is not full raw-event reproducibility.** The scenarios, frozen predictions and engine are in Git, so someone can repeat the experiment on their own machine and obtain new results. They cannot recover or audit the original event streams.
- **`RAW_HASHES.sha256` proves only that particular raw files existed with particular hashes.** It does not let anyone check their content.

## What can be reproduced and what is gone

| Item | Status |
|---|---|
| Engine source, scenario definitions, frozen predictions, the scorer (`evaluation/evaluate.py`), the harness and stress tool | In Git. Anyone can build the engine and **repeat the experiment on their own machine**, which gives new results, not these ones |
| Recorded scores, reports, per-detector counts, latency, resource and `bpf_stats` summaries, stress step results | In this folder, as written by the harness |
| Alert-level summary, scenario-window event excerpts (3 runs), stress event counts, everyday file-open counts | In this folder. Derived once from the raw data, which cannot now be consulted to check them again |
| Hashes of the code that produced each run, and of the predictions in force | In this folder (`env.redacted.txt`, `label_hashes.json`) |
| Raw event streams (`events.jsonl`, `normalized.jsonl`), full alerts with ancestry and command lines (`alerts.jsonl`, `alerts.stamped.tsv`), `loader.stderr`, `runner.stderr`, `normalizer.stderr`, action logs | **Permanently deleted**, never published |
| Re-scoring a run, re-deriving the derived files, tracing a Table 6 cause beyond the excerpts | **Not possible** after deletion |
| Content of any discarded file | **Not recoverable**; `RAW_HASHES.sha256` only proves that a file with that hash existed |

## Layout

| Folder or file | Contents |
|---|---|
| `original/` | Original set (28 attack scenarios, 1 benign smoke), run `20261030-223359-eval` |
| `threat-model/` | The 8 scenarios S30 to S37, run `20261031-165318-eval` (called the independent group in the repository) |
| `nearmiss/` | 8 benign near-miss scenarios, run `20261031-154507-eval` |
| `everyday/run1`, `run2`, `run3` | The three one-hour developer workloads: `20261031-124113-eval`, `20261031-134223-eval`, `20261031-144329-eval`; `SUMMARY.txt` pools them |
| `stress/` | Stepped exec-rate test, run `20261031-171536-stress` |
| `early-runs/` | `scores.json` and `report.md` only, of the three earlier runs `20261029-164811-eval`, `20261029-170342-eval`, `20261030-212225-eval` |
| `live-tests/` | `report.txt` of the live tests for each detector (d1 to d10), the cleanup runs, the ATT&CK mapping check (`mitre`) and the telemetry tests (`tel1`, `tel2`, `tel2-final`) |
| `methodology/` | Evidence for the harness-change and rescoring statement; see `RESCORE_NOTES.md` |
| `VERIFICATION.md` | The checks made on this package, with results |
| `MANIFEST.sha256` | SHA-256 of every file in this folder except itself |
| `RAW_HASHES.sha256` | SHA-256 of the raw files that were discarded (see above) |

Files inside each run folder (not every folder has every file):

| File | What it is | Altered? |
|---|---|---|
| `scores.json`, `report.md` | Scorer output: outcomes per scenario, groups, per-detection counts, frozen-prediction comparison, latency, resources | No, byte for byte as written |
| `stats.json` | Runner counters: alerts and counters per detector, events processed, graph size | No |
| `bpf_stats.json` | Per-program run counts and total run time read from the kernel | No |
| `resources.csv` | One row per second of CPU ticks and memory of the loader, normalizer and runner (not kept for the everyday runs) | No |
| `scenario_windows.json` | Start and end kernel timestamp of each scenario window, harness process ids | No |
| `scenarios_snapshot/` | The scenario definitions as they were when the run started, whose hashes are in `label_hashes.json` | No |
| `steps.json`, `stress_report.md` | Stress run: per-step results and report | No |
| `label_hashes.json` | sha256 of each scenario file, of the whole label set and of the frozen `predictions.json` | Two fields removed (local absolute paths) |
| `env.redacted.txt` | Kernel, python, pipeline mode, `loader_sha256`, and sha256 of every source file used | Lines starting `pipeline ` and `bpftool:` removed (local absolute paths) |
| `alerts.summary.tsv` | One row per alert: detection, technique, trigger time, arrival time, latency, triggering process name, sanitized executable, scenario window and how the scorer classified it | Derived (see below) |
| `event_excerpts.tsv` | `original`, `threat-model`, `nearmiss` only: the events inside each scenario window, without command lines | Derived |
| `file_open_summary.tsv` | `everyday` only: count of file-open events by path and process name | Derived |
| `event_counts.csv` | `stress` only: event counts per step | Derived |

## Which files support which claim of the paper

| Paper claim | Where to look |
|---|---|
| Original set: 18 of 18 ordinary detected, 0 of 10 gap detected, 21 alerts none false, pooled 18 of 28 (0.643), all 29 predictions matched (Table 3, Sections 6.1, 1) | `original/scores.json` (`groups`, `pooled`, `predictions`), `original/report.md`, `original/stats.json` (alerts per detector) |
| Threat-model set: 2 of 8 detected (S33, S36), 3 alerts none false, 6 of 8 predictions failed, S35 scored as a miss | `threat-model/scores.json`, `threat-model/report.md`, `threat-model/scenarios_snapshot/S35_cron_persistence.json` |
| Near-miss set: 5 false alerts (N02, N03, N05, N07, N08), 3 clean, 8 of 8 predictions matched | `nearmiss/scores.json`, `nearmiss/report.md` |
| Everyday workload: 154, 158, 154 false alerts, 466 in 3.000 h, 155.33 per hour, frozen prediction of none | `everyday/run*/scores.json` (`benign`, `predictions`), `everyday/SUMMARY.txt` |
| 463 of the 466 alerts are `rapid_spawn`, 3 are the machine's own `cron` opening `/etc/shadow` | `everyday/run*/scores.json` (`per_detection`), `everyday/run*/alerts.summary.tsv` (`trigger_comm`), `everyday/run1/file_open_summary.tsv` |
| 8 of the 10 detectors raised nothing in three hours | `everyday/run*/stats.json` (`detections`) |
| 1,361 `/etc/passwd` opens in one run that the second file-access tier could not evaluate | `everyday/run1/file_open_summary.tsv` (1,361 opens of `/etc/passwd`, plus 1 of `/etc/shadow` by `cron`) and `everyday/run1/stats.json` (counter `persist_read_only` = 1361). The package shows the opens and the counter; it does not identify which "tier" or detector evaluated them |
| Latency, Table 4 | `*/alerts.summary.tsv` (`latency_ms`, nearest-rank p50 and p95 as in `evaluate.py`) and `*/scores.json` (`latency`) |
| Stress, Table 5 and Figure 3: achieved rate, events per second, 0 lost, runner CPU and memory | `stress/steps.json`, `stress/stress_report.md`, `stress/resources.csv` |
| 706,522 events in the stress run, 0 lost | `stress/steps.json` (`totals`), `stress/event_counts.csv` |
| Exec records matched or exceeded the spawns the generator completed | `stress/event_counts.csv` (per step the number of `/bin/true` exec successes by the single spawn parent equals the number of completed spawns) |
| Privilege-escalation tracker evicted state 227,314 times | `stress/stats.json` (`counters.priv_state_evicted`) |
| Kernel programs about 15.5 µs per exec attempt, 0.56 and 0.67 µs for the open hooks | `stress/bpf_stats.json` (`run_time_ns` divided by `run_cnt`) |
| Everyday run 1: runner 0.199 % of a core, about 110 MB, 25.1 events per second, peak 924 | `everyday/run1/scores.json` (`resources`), `everyday/run1/report.md` |
| 95 of 3,094 opens with a blank path at entry, none at exit | `live-tests/tel2.report.txt` (entry mode: `openat_blank=95` of `openat_seen=3094`), `live-tests/tel2-final.report.txt` (exit mode: `openat_blank=0` of 3094) |
| Live-test results cited in `docs/` (19, 26, 32, 24, 33, 23, 29, 70, 40 and 52 checks, 0 failed) | `live-tests/d1.report.txt` to `d10.report.txt` |
| Predictions were frozen before each run | `label_hashes.json` holds the sha256 of the predictions file in force at run time; `VERIFICATION.md` shows it equals the hash of the predictions file in Git. The order of commits is in the Git history |
| Rescoring five saved runs with old and new code gave byte-identical scores | `methodology/oldcode-vs-newcode.txt`, explained in `methodology/RESCORE_NOTES.md` |
| Which code produced a run | `*/env.redacted.txt` (`loader_sha256` and a sha256 per source file) |
| Detection-gap causes in Table 6 ("traced" statuses) | `original/event_excerpts.tsv`, `threat-model/event_excerpts.tsv`. They show the events recorded in each scenario window (type, time, process name, parent name, sanitized executable or path). The package does not contain the per-scenario analysis, and it was not repeated for this package |

## How the derived files were made

- `alerts.summary.tsv`: from `alerts.stamped.tsv`. `latency_ms` is arrival time minus the triggering event's kernel timestamp, as in the paper. `window` and `class` use the scorer's own rules (`evaluate.py`): the window containing the alert's `ts_ns`, then marker or harness attribution, then `tp`, `acceptable`, `fp`, `in_window_unmarked`, `harness` or `outside_window`. For the stress run `window` is the step and `class` is `in_step_window` or `outside_step_window` (the stress run scores nothing). No command lines, arguments or ancestry are kept; `trigger_exe` is the alert process's executable path after path sanitizing.
- `event_excerpts.tsv`: from `normalized.jsonl`, all events whose `ts_ns` falls inside a scenario window. Columns: scenario, `ts_ns`, event type, pid, ppid, `parent_comm` (the process name last seen for the ppid at that time), `comm`, uid, executable or path (sanitized), and a small detail field (exit code; open flags and return value; connect family and destination class `loopback`, `private`, `linklocal` or `public`; syscall and ids for privilege changes; reason for a failed exec). Command lines, arguments, addresses and ports are not kept.
- `event_counts.csv`: from the stress `events.jsonl`. Events are assigned to a step by `ts_ns` inside the step window of `steps.json`; `lost` records are counted separately. The spawn parent is identified from the events, not from `steps.json` (see "Known discrepancies").
- `file_open_summary.tsv`: from the everyday `events.jsonl`, `file_open` events counted by path and process name.
- Sanitizing rules for paths: `/mnt/<drive>/Users/<name>` and any `/home/<name>` other than the test fixtures `/home/evt_*` are replaced with `<user>`; the author's user name, host name and surname are replaced with `<redacted>`; the one non-loopback test address in `live-tests/d7.report.txt` is replaced with `<private-test-addr>`.

## Known discrepancies and limits

1. **Rescoring files.** `methodology/rescore-result.txt` lists `DIFFERENT` for seven files while `oldcode-vs-newcode.txt` lists `OLD==NEW` for all. They compare different things; `methodology/RESCORE_NOTES.md` has the explanation. The paper's statement matches `oldcode-vs-newcode.txt`. "Five saved runs" is four distinct runs plus a copy of the original run.
2. **Stress spawn parent.** `stress/steps.json` and `stress/stress_report.md` name process id 84256 as the single parent of all spawns, but no event carries that id; all 235,497 `/bin/true` exec successes inside the step windows have parent 86179 (an exec of `python3`). The harness records ids as its own pid namespace shows them, while the kernel programs record ids from the initial pid namespace, and the two differ by 1844 to 1923 on this machine, growing over the day. That mechanism is established; the exact 84256 to 86179 correspondence is inferred, not recorded. No reported number depends on the id. Details, evidence and limits: `methodology/PID_NAMESPACE_NOTES.md`. The files are published unchanged.
3. **Stale text in a tracked file.** `evaluation/independent/PREDICTIONS.md` quotes a label-set hash and then adds a parenthetical saying it is "to be computed ... and filled in before the first run". The quoted hash equals the one recorded for the run in `threat-model/label_hashes.json` and `threat-model/scores.json`, so the parenthetical is left over. Git history shows the file has a single version, committed at 16:52:42 on 2026-10-31 (commit `8a25280`) with the hash and the parenthetical already present; the run started at 16:53:18, 36 seconds later. The file is part of the frozen set, so it was deliberately not edited; this note is the correction.
4. **Open lint note.** The paper says a lint finding was open when the threat-model predictions were frozen and that no lint output was saved. Nothing in this folder addresses it.
5. **Not retained.** Everyday and stress event streams are kept only as the aggregates above. Event excerpts exist for the original, threat-model and near-miss runs only. The three early runs have scores and reports only. The unit-test outputs and baseline source snapshot of the harness-change task were not kept.
6. **Pooled everyday rate.** The per-run reports use window time (3600.107 s and so on); `SUMMARY.txt` pools to 3.0001 h. The paper's "3.000 h" is that value rounded.

## Checking the package

```
cd evaluation/evidence
sha256sum -c MANIFEST.sha256
```

`MANIFEST.sha256` lists every file here except itself. Checking `RAW_HASHES.sha256` is not possible, because the raw files are not available.
