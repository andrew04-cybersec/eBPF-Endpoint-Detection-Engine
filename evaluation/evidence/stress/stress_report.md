# Stress report: 20261031-171536-stress

Stepped exec rate test of the pipeline. Kernel 6.6.87.2-microsoft-standard-WSL2. Steps of 30 s with 10 s idle gaps, 32 worker threads, targets 100 250 500 1000 2000 4000 execs per second.

Clock check: passed.

## Steps

| step | target/s | window s | attempted | completed | achieved/s | events/s | peak events/s | lost events | loader CPU % mean / p95 | normalizer CPU % mean / p95 | runner CPU % mean / p95 | runner max RSS kB | alerts | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 100 | 29.991 | 3000 | 3000 | 100.0 | 300.091 | 300 | 0 (0 dropped) | 0.516 / 0.999 | 1.687 / 1.999 | 2.031 / 2.998 | 27200 | 1 | ok |
| 2 | 250 | 29.997 | 7500 | 7500 | 250.0 | 750.082 | 750 | 0 (0 dropped) | 1.177 / 1.999 | 3.602 / 3.998 | 4.564 / 4.998 | 44640 | 1 | ok |
| 3 | 500 | 29.999 | 15000 | 15000 | 500.0 | 1500.668 | 1518 | 0 (0 dropped) | 1.998 / 2.999 | 6.442 / 6.997 | 8.888 / 10.993 | 74208 | 2 | ok |
| 4 | 1000 | 30.0 | 30000 | 30000 | 1000.0 | 3000.04 | 3000 | 0 (0 dropped) | 4.203 / 4.998 | 14.226 / 17.992 | 20.426 / 26.987 | 130264 | 1 | ok |
| 5 | 2000 | 30.0 | 60000 | 60000 | 2000.0 | 5999.993 | 6001 | 0 (0 dropped) | 7.582 / 8.996 | 24.951 / 29.984 | 37.839 / 45.981 | 218412 | 1 | ok |
| 6 | 4000 | 30.004 | 119997 | 119997 | 3999.4 | 11998.196 | 12516 | 0 (0 dropped) | 13.474 / 14.993 | 42.697 / 43.973 | 70.059 / 73.96 | 235108 | 1 | ok (3 late slots skipped) |

CPU is percent of one core, taken from sampler rows that lie inside the step window. Events per second counts events by their own timestamp inside the window, lost records excluded. A lost event is a loader record saying that events were dropped, and the dropped count is the number of records it reports.

Whole run: 706522 events, 0 lost events (0 dropped records), of which 0 lost events (0 dropped records) could not be placed in a step window. Alerts: 7 in total, 7 inside step windows, 0 outside.

Alerts inside step windows by detection (not scored): rapid_spawn 6, sensitive_file_access 1.

Loader lines about lost events and drops: loader: file_stats mode=exit openat_seen=708546 openat_blank=0 file_open_emitted=9 write_list_emitted=0 write_list_skipped_readonly=9

## Reading these results

- Stress results are separate from detection accuracy. No scenario is run, no label is used, and no recall or precision is computed. They are not pooled with any scenario result.
- Alerts raised during a step (rapid_spawn is the expected example) are side effects of the load. They are counted and listed for the record and are not scored.
- Only measured rates are claimed. A step's achieved rate is the completed spawns divided by the step window. The target rate is a setting and not a result.
- Nothing is extrapolated beyond the highest rate measured: 3999.4 execs per second achieved in the step with target 4000. Nothing is stated about higher rates.
- Every planned step is listed above, including steps with lost events, partial steps and steps that were not run, each with its reason.

## Where the spawns come from

All spawns come from 1 distinct parent process: the stress.py process (pid 84256), which the driver starts as its only child for the stress run. The worker threads belong to that process and add no parents. Each spawn is a direct child of it running /bin/true from an argument list, with no shell.

## Caps applied

Target rate at most 5000 per second, step at most 120 s, at most 64 worker threads. A slot more than 50 ms behind its time is skipped and counted, never run in a catch-up burst. The run is told to stop when free disk space on the results folder falls below 2147483648 bytes or available memory falls below 524288 kB; neither floor was reached in this run.

bpf_stats were read once at the end of the run and are in bpf_stats.json (available: True). The run is one machine, so the numbers are approximate.
