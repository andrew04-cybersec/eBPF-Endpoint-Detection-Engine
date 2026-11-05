# Evaluation report: 20261030-212225-eval

Pipeline mode: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Label set hash: 1ca388582d690b1d9d0137170007cbb28a19138a638170b870a73c74173905d6.
Alerts read: 2 (0 unreadable lines). Scenarios not run: none.

Clock check: passed. Largest distance outside the bracket: 0 ns.

## Scenario outcomes

| scenario | kind | technique | outcome | true positive alerts | acceptable alerts | false positive alerts | unmet expectations | timed out | window s | known gap |
|---|---|---|---|---|---|---|---|---|---|---|
| S01_shell_from_service_after_loader | attack | T1059.004 | detected | shell_from_service 1 | none | none | - | no | 0.008 | - |
| S02_shell_from_service_before_loader | attack | T1059.004 | missed | none | none | none | shell_from_service needs 1, got 0 | no | 1.019 | The service was started before the loader, so the loader never saw it start. Its node in the graph is a placeholder with no name, and shell_from_service and unusual_ancestry cannot evaluate the shell (they count it as unevaluable). |
| S03_download_chmod_exec | attack | T1105 | detected | download_chmod_exec 1 | none | none | - | no | 0.066 | - |
| S04_exec_from_tmp_via_interpreter | attack | T1059 | missed | none | none | none | exec_from_tmp needs 1, got 0 | no | 0.032 | The program that is executed is /usr/bin/python3, and the script is only an argument. exec_from_tmp looks at the executed filename only, so an interpreter running a script from /tmp is not seen. |
| S05_benign_smoke | benign | n/a | clean | none | none | none | - | no | 20.063 | - |

## Per technique (attack scenarios)

| technique | attacks | detected | missed | recall |
|---|---|---|---|---|
| T1059 | 1 | 0 | 1 | 0/1 (0.000) |
| T1059.004 | 2 | 1 | 1 | 1/2 (0.500) |
| T1105 | 1 | 1 | 0 | 1/1 (1.000) |

## Per detection

| detection | expected in | detected in | scenario recall | TP | FP | acceptable | precision (lenient) | precision (strict) |
|---|---|---|---|---|---|---|---|---|
| download_chmod_exec | 1 | 1 | 1/1 (1.000) | 1 | 0 | 0 | 1/1 (1.000) | 1/1 (1.000) |
| exec_from_tmp | 1 | 0 | 0/1 (0.000) | 0 | 0 | 0 | 0/0 (n/a) | 0/0 (n/a) |
| shell_from_service | 2 | 1 | 1/2 (0.500) | 1 | 0 | 0 | 1/1 (1.000) | 1/1 (1.000) |

Pooled recall (scenario level): 2/4 (0.500). Pooled precision (alert level): lenient 2/2 (1.000), strict 2/2 (1.000).

## Benign runs

False positive alerts in benign scenarios: 0 over 20.063 s of benign run time; false positives per hour: 0.0.

## Latency (alert arrival at the harness minus the ts_ns of the triggering event)

Pipeline mode for these numbers: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Negative values (clock disagreement): 0.

| alerts | n | p50 ms | p95 ms | max ms |
|---|---|---|---|---|
| all | 2 | 0.704 | 89.913 | 89.913 |
| true_positive | 2 | 0.704 | 89.913 | 89.913 |

## Resources

| process | samples | CPU % of one core, mean | CPU % p95 | max RSS kB | peak VmHWM kB |
|---|---|---|---|---|---|
| loader | 33 | 0.031 | 0.0 | 10960 | 14880 |
| normalizer | 33 | 0.031 | 0.0 | 12480 | 12480 |
| runner | 33 | 0.062 | 0.999 | 13120 | 13120 |

Events per second: 116 events over 32 s, mean 3.625, p95 17, peak 18.
Ring buffer drops: 0 lost events, 0 records dropped in total. Loader lines: loader: file_stats mode=exit openat_seen=1392 openat_blank=0 file_open_emitted=1 write_list_emitted=0 write_list_skipped_readonly=0

## bpf_stats (per BPF program, read while the loader was running)

| program | name bpftool returned | run count | total ns | mean ns per run | count from the run's own data | status |
|---|---|---|---|---|---|---|
| handle_connect | handle_connect | 3 | 19152 | 6384.0 | - | counts |
| handle_exec_attempt | handle_exec_attempt | 47 | 773410 | 16455.5 | exec_attempt events 47 | counts |
| handle_exec_success | handle_exec_success | 32 | 528911 | 16528.5 | exec_success events 32 | counts |
| handle_exit | handle_exit | 35 | 694002 | 19828.6 | - | counts |
| handle_openat_exit | handle_openat_exit | 1380 | 443458 | 321.3 | openat_seen 1392 | counts |
| handle_openat_save | handle_openat_save | 1380 | 414354 | 300.3 | openat_seen 1392 | counts |
| handle_setgid | handle_setgid | n/a | n/a | n/a | - | no data from bpftool |
| handle_setresgid | handle_setresgid | n/a | n/a | n/a | - | no data from bpftool |
| handle_setresuid | handle_setresuid | n/a | n/a | n/a | - | no data from bpftool |
| handle_setreuid | handle_setreuid | n/a | n/a | n/a | - | no data from bpftool |
| handle_setuid | handle_setuid | n/a | n/a | n/a | - | no data from bpftool |

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
