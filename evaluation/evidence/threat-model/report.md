# Evaluation report: 20261031-165318-eval

Pipeline mode: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Label set hash: 9b3bcb6d47ddf6a1aad681e31522a2a929b980b71b28b122f561a2bc6e3eebcb.
Alerts read: 3 (0 unreadable lines). Scenarios not run: none.

Clock check: passed. Largest distance outside the bracket: 0 ns.

## Headline: attack scenarios by group

| group | scenarios | detected | missed | recall |
|---|---|---|---|---|
| ordinary | 0 | 0 | 0 | 0/0 (n/a) |
| gap | 0 | 0 | 0 | 0/0 (n/a) |
| independent | 8 | 2 | 6 | 2/8 (0.250) |

The ordinary group was written by the same person who read the detection rules, so its recall is a best case and not a detection rate. The gap group is built to miss: its scenarios exercise documented gaps, so a miss there is an expected result and not a harness error. The two groups are never added into one score here.

The independent group is reported on its own row and is not added into the ordinary or gap rows.

## Scenario outcomes

| scenario | kind | group | technique | outcome | true positive alerts | acceptable alerts | false positive alerts | unmet expectations | alerts in window without the marker | timed out | window s | known gap |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| S30_service_shell | attack | independent | T1059.004 | missed | none | none | none | shell_from_service needs 1, got 0 | 0 | no | 1.066 | - |
| S31_payload_transfer | attack | independent | T1105 | missed | none | none | none | download_chmod_exec needs 1, got 0 | 0 | no | 0.008 | - |
| S32_password_material | attack | independent | T1003.008 | missed | none | none | none | sensitive_file_access needs 1, got 0 | 0 | no | 0.016 | - |
| S33_private_key_harvest | attack | independent | T1552.004 | detected | sensitive_file_access 1 | none | none | - | 0 | no | 0.032 | - |
| S34_raw_command_channel | attack | independent | T1095 | missed | none | none | none | outbound_after_exec needs 1, got 0 | 0 | no | 0.114 | - |
| S35_cron_persistence | attack | independent | T1053.003 | missed | persistence_write 1 | none | none | persistence_command needs 1, got 0 | 0 | no | 0.004 | - |
| S36_shell_startup | attack | independent | T1546.004 | detected | persistence_write 1 | none | none | - | 0 | no | 0.016 | - |
| S37_dynamic_linker_hijack | attack | independent | T1574.006 | missed | none | none | none | persistence_write needs 1, got 0 | 0 | no | 0.032 | - |

A count above 0 in the column of alerts in the window without the marker means the scenario's evidence is not attributable by its marker; those alerts are listed below and are not scored.

## Scenarios not run

none

## Per technique (attack scenarios)

| technique | attacks | detected | missed | recall | ordinary | gap | independent |
|---|---|---|---|---|---|---|---|
| T1003.008 | 1 | 0 | 1 | 0/1 (0.000) | 0/0 (n/a) | 0/0 (n/a) | 0/1 (0.000) |
| T1053.003 | 1 | 0 | 1 | 0/1 (0.000) | 0/0 (n/a) | 0/0 (n/a) | 0/1 (0.000) |
| T1059.004 | 1 | 0 | 1 | 0/1 (0.000) | 0/0 (n/a) | 0/0 (n/a) | 0/1 (0.000) |
| T1095 | 1 | 0 | 1 | 0/1 (0.000) | 0/0 (n/a) | 0/0 (n/a) | 0/1 (0.000) |
| T1105 | 1 | 0 | 1 | 0/1 (0.000) | 0/0 (n/a) | 0/0 (n/a) | 0/1 (0.000) |
| T1546.004 | 1 | 1 | 0 | 1/1 (1.000) | 0/0 (n/a) | 0/0 (n/a) | 1/1 (1.000) |
| T1552.004 | 1 | 1 | 0 | 1/1 (1.000) | 0/0 (n/a) | 0/0 (n/a) | 1/1 (1.000) |
| T1574.006 | 1 | 0 | 1 | 0/1 (0.000) | 0/0 (n/a) | 0/0 (n/a) | 0/1 (0.000) |

## Per detection

| detection | expected in | detected in | scenario recall | TP | FP | acceptable | precision (lenient) | precision (strict) |
|---|---|---|---|---|---|---|---|---|
| download_chmod_exec | 1 | 0 | 0/1 (0.000) | 0 | 0 | 0 | 0/0 (n/a) | 0/0 (n/a) |
| exec_from_tmp | 0 | 0 | 0/0 (n/a) | 0 | 0 | 0 | 0/0 (n/a) | 0/0 (n/a) |
| interpreter_chain | 0 | 0 | 0/0 (n/a) | 0 | 0 | 0 | 0/0 (n/a) | 0/0 (n/a) |
| outbound_after_exec | 1 | 0 | 0/1 (0.000) | 0 | 0 | 0 | 0/0 (n/a) | 0/0 (n/a) |
| persistence_command | 1 | 0 | 0/1 (0.000) | 0 | 0 | 0 | 0/0 (n/a) | 0/0 (n/a) |
| persistence_write | 3 | 2 | 2/3 (0.667) | 2 | 0 | 0 | 2/2 (1.000) | 2/2 (1.000) |
| rapid_spawn | 0 | 0 | 0/0 (n/a) | 0 | 0 | 0 | 0/0 (n/a) | 0/0 (n/a) |
| sensitive_file_access | 2 | 1 | 1/2 (0.500) | 1 | 0 | 0 | 1/1 (1.000) | 1/1 (1.000) |
| shell_from_service | 1 | 0 | 0/1 (0.000) | 0 | 0 | 0 | 0/0 (n/a) | 0/0 (n/a) |
| unusual_ancestry | 0 | 0 | 0/0 (n/a) | 0 | 0 | 0 | 0/0 (n/a) | 0/0 (n/a) |

Pooled recall (scenario level, secondary): 2/8 (0.250). Pooled precision (alert level): lenient 3/3 (1.000), strict 3/3 (1.000).
The pooled numbers mix the ordinary and the gap group, and the mix is a design choice and not a population, so they are secondary to the group tables above.

## Predicted versus actual

| scenario | predicted | actual | other alerts predicted | other alerts actual | status |
|---|---|---|---|---|---|
| S30_service_shell | detected | missed | none | none | MISMATCH |
| S31_payload_transfer | detected | missed | none | none | MISMATCH |
| S32_password_material | detected | missed | none | none | MISMATCH |
| S33_private_key_harvest | detected | detected | none | none | MATCH |
| S34_raw_command_channel | detected | missed | none | none | MISMATCH |
| S35_cron_persistence | detected | missed | none | none | MISMATCH |
| S36_shell_startup | detected | detected | none | none | MATCH |
| S37_dynamic_linker_hijack | detected | missed | none | none | MISMATCH |

Mismatches (listed, never scored): S30_service_shell, S31_payload_transfer, S32_password_material, S34_raw_command_channel, S35_cron_persistence, S37_dynamic_linker_hijack.

## Benign runs

False positive alerts in benign scenarios: 0 over 0.0 s of benign run time; false positives per hour: n/a.

## Latency (alert arrival at the harness minus the ts_ns of the triggering event)

Pipeline mode for these numbers: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Negative values (clock disagreement): 0.

| alerts | n | p50 ms | p95 ms | max ms |
|---|---|---|---|---|
| all | 3 | 0.431 | 0.604 | 0.604 |
| true_positive | 3 | 0.431 | 0.604 | 0.604 |

## Resources

| process | samples | CPU % of one core, mean | CPU % p95 | max RSS kB | peak VmHWM kB |
|---|---|---|---|---|---|
| loader | 19 | 0.0 | 0.0 | 10960 | 14880 |
| normalizer | 19 | 0.055 | 0.999 | 12640 | 12640 |
| runner | 19 | 0.111 | 1.997 | 13120 | 13120 |

Events per second: 142 events over 18 s, mean 7.889, p95 40, peak 40.
Ring buffer drops: 0 lost events, 0 records dropped in total. Loader lines: loader: file_stats mode=exit openat_seen=3028 openat_blank=0 file_open_emitted=6 write_list_emitted=2 write_list_skipped_readonly=7

## bpf_stats (per BPF program, read while the loader was running)

| program | name bpftool returned | run count | total ns | mean ns per run | count from the run's own data | status |
|---|---|---|---|---|---|---|
| handle_connect | handle_connect | 15 | 8587 | 572.5 | - | counts |
| handle_exec_attempt | handle_exec_attempt | 66 | 978317 | 14823.0 | exec_attempt events 66 | counts |
| handle_exec_success | handle_exec_success | 39 | 505709 | 12966.9 | exec_success events 39 | counts |
| handle_exit | handle_exit | 31 | 620248 | 20008.0 | - | counts |
| handle_openat_exit | handle_openat_exit | 3014 | 1101666 | 365.5 | openat_seen 3028 | counts |
| handle_openat_save | handle_openat_save | 3014 | 729479 | 242.0 | openat_seen 3028 | counts |
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
