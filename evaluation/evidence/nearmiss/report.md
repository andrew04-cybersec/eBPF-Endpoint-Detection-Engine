# Evaluation report: 20261031-154507-eval

Pipeline mode: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Label set hash: f419657963f3ea5eb19d2327d62e7bf86e0013becea4fdfb974c47ebe9327fcc.
Alerts read: 5 (0 unreadable lines). Scenarios not run: none.

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
| N01_install_local_prefix | benign | n/a | n/a | clean | none | none | none | - | 0 | no | 0.016 | - |
| N02_install_staged_in_tmp | benign | n/a | n/a | false alerts | none | none | exec_from_tmp 1 | - | 0 | no | 0.064 | - |
| N03_parallel_build_j200 | benign | n/a | n/a | false alerts | none | none | rapid_spawn 1 | - | 0 | no | 0.315 | - |
| N04_sed_inplace_bashrc | benign | n/a | n/a | clean | none | none | none | - | 0 | no | 0.064 | - |
| N05_append_bashrc_redirect | benign | n/a | n/a | false alerts | none | none | persistence_write 1 | - | 0 | no | 0.032 | - |
| N06_sshkeygen_fake_home | benign | n/a | n/a | clean | none | none | none | - | 0 | no | 0.008 | - |
| N07_cat_ssh_key_nonlisted_reader | benign | n/a | n/a | false alerts | none | none | sensitive_file_access 1 | - | 0 | no | 0.004 | - |
| N08_root_cat_shadow | benign | n/a | n/a | false alerts | none | none | sensitive_file_access 1 | - | 0 | no | 0.004 | - |

A count above 0 in the column of alerts in the window without the marker means the scenario's evidence is not attributable by its marker; those alerts are listed below and are not scored.

## Scenarios not run

none

## Per technique (attack scenarios)

| technique | attacks | detected | missed | recall | ordinary | gap |
|---|---|---|---|---|---|---|

## Per detection

| detection | expected in | detected in | scenario recall | TP | FP | acceptable | precision (lenient) | precision (strict) |
|---|---|---|---|---|---|---|---|---|
| exec_from_tmp | 0 | 0 | 0/0 (n/a) | 0 | 1 | 0 | 0/1 (0.000) | 0/1 (0.000) |
| persistence_write | 0 | 0 | 0/0 (n/a) | 0 | 1 | 0 | 0/1 (0.000) | 0/1 (0.000) |
| rapid_spawn | 0 | 0 | 0/0 (n/a) | 0 | 1 | 0 | 0/1 (0.000) | 0/1 (0.000) |
| sensitive_file_access | 0 | 0 | 0/0 (n/a) | 0 | 2 | 0 | 0/2 (0.000) | 0/2 (0.000) |

Pooled recall (scenario level, secondary): 0/0 (n/a). Pooled precision (alert level): lenient 0/5 (0.000), strict 0/5 (0.000).
The pooled numbers mix the ordinary and the gap group, and the mix is a design choice and not a population, so they are secondary to the group tables above.

## Predicted versus actual

| scenario | predicted | actual | other alerts predicted | other alerts actual | status |
|---|---|---|---|---|---|
| N01_install_local_prefix | no alerts | no alerts | none | none | MATCH |
| N02_install_staged_in_tmp | false alerts | false alerts | exec_from_tmp | exec_from_tmp | MATCH |
| N03_parallel_build_j200 | false alerts | false alerts | rapid_spawn | rapid_spawn | MATCH |
| N04_sed_inplace_bashrc | no alerts | no alerts | none | none | MATCH |
| N05_append_bashrc_redirect | false alerts | false alerts | persistence_write | persistence_write | MATCH |
| N06_sshkeygen_fake_home | no alerts | no alerts | none | none | MATCH |
| N07_cat_ssh_key_nonlisted_reader | false alerts | false alerts | sensitive_file_access | sensitive_file_access | MATCH |
| N08_root_cat_shadow | false alerts | false alerts | sensitive_file_access | sensitive_file_access | MATCH |

Mismatches (listed, never scored): none.

## Benign runs

False positive alerts in benign scenarios: 5 over 0.506 s of benign run time; false positives per hour: 35557.474.

## Latency (alert arrival at the harness minus the ts_ns of the triggering event)

Pipeline mode for these numbers: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Negative values (clock disagreement): 0.

| alerts | n | p50 ms | p95 ms | max ms |
|---|---|---|---|---|
| all | 5 | 0.611 | 1.207 | 1.207 |
| true_positive | 0 | n/a | n/a | n/a |

## Resources

| process | samples | CPU % of one core, mean | CPU % p95 | max RSS kB | peak VmHWM kB |
|---|---|---|---|---|---|
| loader | 18 | 0.059 | 0.998 | 10800 | 14880 |
| normalizer | 18 | 0.352 | 4.989 | 12640 | 12640 |
| runner | 18 | 0.587 | 7.982 | 15200 | 15200 |

Events per second: 2113 events over 17 s, mean 124.294, p95 2009, peak 2009.
Ring buffer drops: 0 lost events, 0 records dropped in total. Loader lines: loader: file_stats mode=exit openat_seen=1859 openat_blank=0 file_open_emitted=8 write_list_emitted=1 write_list_skipped_readonly=1

## bpf_stats (per BPF program, read while the loader was running)

| program | name bpftool returned | run count | total ns | mean ns per run | count from the run's own data | status |
|---|---|---|---|---|---|---|
| handle_connect | handle_connect | 6 | 2029 | 338.2 | - | counts |
| handle_exec_attempt | handle_exec_attempt | 451 | 1333074 | 2955.8 | exec_attempt events 451 | counts |
| handle_exec_success | handle_exec_success | 427 | 5406824 | 12662.4 | exec_success events 427 | counts |
| handle_exit | handle_exit | 426 | 5266365 | 12362.4 | - | counts |
| handle_openat_exit | handle_openat_exit | 1846 | 976423 | 528.9 | openat_seen 1859 | counts |
| handle_openat_save | handle_openat_save | 1847 | 708478 | 383.6 | openat_seen 1859 | counts |
| handle_setgid | handle_setgid | n/a | n/a | n/a | - | no data from bpftool |
| handle_setresgid | handle_setresgid | 400 | 230897 | 577.2 | - | counts |
| handle_setresuid | handle_setresuid | 400 | 4967187 | 12418.0 | - | counts |
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
