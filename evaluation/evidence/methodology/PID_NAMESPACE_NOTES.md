# Process ids in the harness records and in the kernel events

`stress/steps.json` and `stress/stress_report.md` name process id **84256** as the single parent of all stress spawns. No event of the run carries that id. In the events, all 235,497 `/bin/true` exec successes inside the step windows have parent **86179**, which is itself an exec of `python3` (the stress generator). This note records what was established about the difference. It was written from the original files before they were discarded and cannot be repeated from the published files.

## What was established

1. **Where 84256 comes from.** `evaluation/stress/run_stress.py` writes `spawn_parent_pid` from `record[0]["pid"]`, and `record` is filled by `run_eval.run_script` with `proc.pid`, the id that Python's `subprocess.Popen` returned to the driver. It is the id the driver sees.
2. **Where 86179 comes from.** The kernel program (`telemetry/src/exec_exit.bpf.c`, lines 54 to 59) takes the id from `bpf_get_current_pid_tgid()`, which reports the id in the kernel's initial pid namespace.
3. **The two numbering spaces differ on this machine.** The driver's own id and the id the kernel events give for the same driver differ in every run where both were recorded. The clock-check marker processes (`/bin/true EVT_EVAL_CLOCK_*`) are children of the driver, so their parent id in the events is the driver's id as the kernel reports it:

| Run (start time) | Driver id recorded by the harness | Parent id of the clock-check markers in the events | Difference |
|---|---|---|---|
| everyday run 1 (12:41) | 28008 | 29852 | 1844 |
| everyday run 2 (13:42) | 46313 | 48180 | 1867 |
| everyday run 3 (14:43) | 64898 | 66785 | 1887 |
| near-miss (15:45) | 83101 | 85007 | 1906 |
| threat-model (16:53) | 83975 | 85893 | 1918 |
| stress (17:15) | `stress.py` id 84256 (from `Popen`) | `python3` id 86179 (from the events) | 1923 (a different pair of processes, same direction) |

   The original set's `scenario_windows.json` records no harness ids, so it gives no pair.
4. **The shell of this machine is in a non-initial pid namespace.** Checked on the same machine after the runs: `/proc/self/ns/pid` is `pid:[4026532221]`, not the kernel's fixed initial pid namespace id `4026531836`, and pid 1 in that namespace is `systemd`. Ids seen from inside that namespace (the harness, `/proc`, `subprocess`) therefore differ from the ids that `bpf_get_current_pid_tgid()` reports.
5. **The difference grows with time.** It rises monotonically from 1844 to 1923 over about four and a half hours, which is what two pid counters would do if processes were being created outside the harness's namespace as well as inside it. This describes the pattern; it does not identify those processes.

## What is not established

- The namespace state at the time of the runs was not recorded; point 4 was checked afterwards on the same machine.
- No record pairs 84256 with 86179 directly. The match is inferred from the pattern in point 3 (the stress pair fits the trend of the other pairs) and from the fact that 86179 is the only parent of the stress spawns.
- The pid difference was not noticed at run time and no code translates between the two numbering spaces.

## Effect on the published numbers

- The id stored in `steps.json` appears only in the line "Where the spawns come from" of `stress_report.md`. No count or rate depends on it. `stress/event_counts.csv` identifies the parent from the events.
- The scorer's `is_harness` function compares an alert's id (kernel view) with the harness ids (driver view) to leave out alerts raised by the harness itself. That comparison can therefore miss. It is used only for scenarios attributed by time window, which here means the three everyday runs. In those runs all 466 alerts were raised by `gcc` (463) or `cron` (3) (`everyday/run*/alerts.summary.tsv`, column `trigger_comm`), none by a harness process, so the exclusion had nothing to exclude and no reported figure changes.
- The resource sampler reads `/proc/<id>` using the driver's ids inside the same namespace, so the CPU and memory figures are not affected.
