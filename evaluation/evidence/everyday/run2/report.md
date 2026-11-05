# Evaluation report: 20261031-134223-eval

Pipeline mode: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Label set hash: 70385b2d0099eba187df859d889e5e171b0da6651c4f030a875a86fdc9c22960.
Alerts read: 158 (0 unreadable lines). Scenarios not run: none.

Clock check: passed. Largest distance outside the bracket: 0 ns.

## Headline: attack scenarios by group

| group | scenarios | detected | missed | recall |
|---|---|---|---|---|
| ordinary | 0 | 0 | 0 | 0/0 (n/a) |
| gap | 0 | 0 | 0 | 0/0 (n/a) |

The ordinary group was written by the same person who read the detection rules, so its recall is a best case and not a detection rate. The gap group is built to miss: its scenarios exercise documented gaps, so a miss there is an expected result and not a harness error. The two groups are never added into one score here.

## Scenario outcomes

| scenario | kind | group | technique | outcome | true positive alerts | acceptable alerts | false positive alerts | unmet expectations | alerts in window without the marker | timed out | window s | known gap |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| E01_everyday_workload | benign | n/a | n/a | false alerts | none | none | rapid_spawn 157, sensitive_file_access 1 | - | 0 | no | 3600.065 | - |

A count above 0 in the column of alerts in the window without the marker means the scenario's evidence is not attributable by its marker; those alerts are listed below and are not scored.

## Scenarios not run

none

## Per technique (attack scenarios)

| technique | attacks | detected | missed | recall | ordinary | gap |
|---|---|---|---|---|---|---|

## Per detection

| detection | expected in | detected in | scenario recall | TP | FP | acceptable | precision (lenient) | precision (strict) |
|---|---|---|---|---|---|---|---|---|
| rapid_spawn | 0 | 0 | 0/0 (n/a) | 0 | 157 | 0 | 0/157 (0.000) | 0/157 (0.000) |
| sensitive_file_access | 0 | 0 | 0/0 (n/a) | 0 | 1 | 0 | 0/1 (0.000) | 0/1 (0.000) |

Pooled recall (scenario level, secondary): 0/0 (n/a). Pooled precision (alert level): lenient 0/158 (0.000), strict 0/158 (0.000).
The pooled numbers mix the ordinary and the gap group, and the mix is a design choice and not a population, so they are secondary to the group tables above.

## Predicted versus actual

| scenario | predicted | actual | other alerts predicted | other alerts actual | status |
|---|---|---|---|---|---|
| E01_everyday_workload | no alerts | false alerts | none | rapid_spawn, sensitive_file_access | MISMATCH |

Mismatches (listed, never scored): E01_everyday_workload.

## Benign runs

False positive alerts in benign scenarios: 158 over 3600.065 s of benign run time; false positives per hour: 157.997.

## Benign runs attributed by window (scripted workload)

Rule: an alert inside the window counts against the rate unless the process that triggered it is a process run_eval.py started itself (harness, listed and not counted); an alert outside every window is machine noise (listed and not counted). No marker is used.
Label: approximate; scripted workload, one machine, WSL2.

### E01_everyday_workload

Window: 1.000018 hours.
Events per hour by type (all processes, the harness included): exec_attempt 42763.224, exec_success 18523.664, exit 18559.663, file_open 1360.975, priv_change 10363.812.
Alerts per detection: rapid_spawn 157, sensitive_file_access 1.
False positives: 158. False positives per hour: 157.997.

Harness alerts inside a window (not counted): 0.

Machine noise, outside every window (not counted): 0.

## Latency (alert arrival at the harness minus the ts_ns of the triggering event)

Pipeline mode for these numbers: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Negative values (clock disagreement): 0.

| alerts | n | p50 ms | p95 ms | max ms |
|---|---|---|---|---|
| all | 158 | 1.104 | 4.284 | 56.614 |
| true_positive | 0 | n/a | n/a | n/a |

## Resources

| process | samples | CPU % of one core, mean | CPU % p95 | max RSS kB | peak VmHWM kB |
|---|---|---|---|---|---|
| loader | 3593 | 0.054 | 0.991 | 10800 | 14880 |
| normalizer | 3593 | 0.111 | 0.999 | 14400 | 14400 |
| runner | 3593 | 0.169 | 0.999 | 110004 | 110004 |

Events per second: 91582 events over 3603 s, mean 25.418, p95 39, peak 909.
Ring buffer drops: 0 lost events, 0 records dropped in total. Loader lines: loader: file_stats mode=exit openat_seen=478223 openat_blank=0 file_open_emitted=1361 write_list_emitted=0 write_list_skipped_readonly=19

## bpf_stats (per BPF program, read while the loader was running)

| program | name bpftool returned | run count | total ns | mean ns per run | count from the run's own data | status |
|---|---|---|---|---|---|---|
| handle_connect | handle_connect | 3308 | 930245 | 281.2 | - | counts |
| handle_exec_attempt | handle_exec_attempt | 42767 | 443030083 | 10359.2 | exec_attempt events 42767 | counts |
| handle_exec_success | handle_exec_success | 18527 | 242774621 | 13103.8 | exec_success events 18527 | counts |
| handle_exit | handle_exit | 18589 | 355967761 | 19149.4 | - | counts |
| handle_openat_exit | handle_openat_exit | 478210 | 174675123 | 365.3 | openat_seen 478223 | counts |
| handle_openat_save | handle_openat_save | 478212 | 141283434 | 295.4 | openat_seen 478223 | counts |
| handle_setgid | handle_setgid | 1 | 21141 | 21141.0 | - | counts |
| handle_setresgid | handle_setresgid | 5181 | 5130873 | 990.3 | - | counts |
| handle_setresuid | handle_setresuid | 5181 | 90510746 | 17469.7 | - | counts |
| handle_setreuid | handle_setreuid | n/a | n/a | n/a | - | no data from bpftool |
| handle_setuid | handle_setuid | 1 | 23341 | 23341.0 | - | counts |

Programs were selected by: names.

Expected programs not found in the bpftool output: none.

The own-data column is the number of exec_attempt or exec_success events in the raw events file, or openat_seen from the loader's stats line. It is printed for comparison and a difference is not an error: bpf_stats was enabled slightly after the loader attached, so the first firings are missing from the run counts.
handle_exit fires once per thread exit and handle_connect once per connect call of any address family, while events are emitted per process and only for IPv4 and IPv6, and the privilege programs fire once per call, so their run counts are shown without a comparison and exceed the events by design.
A status of 'no data from bpftool' means the program was listed but bpftool gave no run_cnt or run_time_ns for it. The bpftool man page does not say that these are left out for a program that has not run, so this is not read as zero runs.

## Unattributed alerts (listed, not scored)

Inside a scenario window without that scenario's marker: 0.

Outside every scenario window: 0.

## What these numbers do not mean

- A handful of scenarios is a demonstration and not a statistical estimate. A ratio such as 3/4 says what happened in these runs only, and a recall of 1 over a few scenarios is not a detection rate.
- Labels follow the threat model, so a miss on a scenario with a documented gap is an expected result of the telemetry and the rules, not a harness error.
- Precision here depends on which scenarios were run. The benign scenarios are short and are not a baseline of normal use, so false positives per hour is not a rate for a real machine.
- Latency is the time from the triggering event (kernel monotonic clock) to the harness reading the alert line, through the loader, normalizer and runner. It is only as valid as the clock check, and it excludes the time before the event.
- CPU, memory and bpf_stats were measured while the pipeline ran with the sampler and the harness itself running; their cost is not subtracted. The bpf_stats numbers cover all programs while bpf_stats was enabled, which adds overhead of its own.
- A service started before the loader is a placeholder node with no name, so detections that need its name cannot judge it. These misses are a property of the design and not of the scoring.
