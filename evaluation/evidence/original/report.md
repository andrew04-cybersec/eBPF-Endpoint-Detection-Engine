# Evaluation report: 20261030-223359-eval

Pipeline mode: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Label set hash: 4dc82dc5803011cbe1724e41bb7edf12dad3603a8daee50041638eb7814b390c.
Alerts read: 21 (0 unreadable lines). Scenarios not run: none.

Clock check: passed. Largest distance outside the bracket: 0 ns.

## Headline: attack scenarios by group

| group | scenarios | detected | missed | recall |
|---|---|---|---|---|
| ordinary | 18 | 18 | 0 | 18/18 (1.000) |
| gap | 10 | 0 | 10 | 0/10 (0.000) |

The ordinary group was written by the same person who read the detection rules, so its recall is a best case and not a detection rate. The gap group is built to miss: its scenarios exercise documented gaps, so a miss there is an expected result and not a harness error. The two groups are never added into one score here.

## Scenario outcomes

| scenario | kind | group | technique | outcome | true positive alerts | acceptable alerts | false positive alerts | unmet expectations | alerts in window without the marker | timed out | window s | known gap |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| S01_shell_from_service_after_loader | attack | ordinary | T1059.004 | detected | shell_from_service 1 | none | none | - | 0 | no | 0.016 | - |
| S02_shell_from_service_before_loader | attack | gap | T1059.004 | missed | none | none | none | shell_from_service needs 1, got 0 | 0 | no | 1.019 | The service was started before the loader, so the loader never saw it start. Its node in the graph is a placeholder with no name, and shell_from_service and unusual_ancestry cannot evaluate the shell (they count it as unevaluable). |
| S03_download_chmod_exec | attack | ordinary | T1105 | detected | download_chmod_exec 1 | none | none | - | 0 | no | 0.032 | - |
| S04_exec_from_tmp_via_interpreter | attack | gap | T1059 | missed | none | none | none | exec_from_tmp needs 1, got 0 | 0 | no | 0.032 | The program that is executed is /usr/bin/python3, and the script is only an argument. exec_from_tmp looks at the executed filename only, so an interpreter running a script from /tmp is not seen. |
| S05_benign_smoke | benign | n/a | n/a | clean | none | none | none | - | 0 | no | 20.072 | - |
| S06_service_runs_python | attack | ordinary | T1059 | detected | unusual_ancestry 1 | none | none | - | 0 | no | 0.033 | - |
| S07_service_shell_python | attack | ordinary | T1059.004 | detected | shell_from_service 1, unusual_ancestry 1 | none | none | - | 0 | no | 0.032 | - |
| S08_nested_inline_interpreters | attack | ordinary | T1059 | detected | interpreter_chain 2 | none | none | - | 0 | no | 0.032 | - |
| S09_nested_script_files | attack | gap | T1059 | missed | none | none | none | interpreter_chain needs 1, got 0 | 0 | no | 0.064 | interpreter_chain requires an inline-code option in some member of the chain. A chain of script files has none, so it is not seen however long it is. |
| S10_download_via_python | attack | gap | T1105 | missed | none | none | none | download_chmod_exec needs 1, got 0 | 0 | no | 0.216 | download_chmod_exec tracks only curl and wget as downloaders, so a download made by python3 creates no entry and the chmod and the exec match nothing. |
| S11_download_relative_path | attack | ordinary | T1105 | detected | download_chmod_exec 1 | none | none | - | 0 | no | 0.016 | - |
| S12_run_from_shm | attack | ordinary | T1059 | detected | exec_from_tmp 1 | none | none | - | 0 | no | 0.004 | - |
| S13_download_to_tmp_and_run | attack | ordinary | T1105 | detected | download_chmod_exec 1, exec_from_tmp 1 | none | none | - | 0 | no | 0.032 | - |
| S14_read_shadow | attack | ordinary | T1003.008 | detected | sensitive_file_access 1 | none | none | - | 0 | no | 0.004 | - |
| S15_read_ssh_private_key | attack | ordinary | T1552.004 | detected | sensitive_file_access 1 | none | none | - | 0 | no | 0.016 | - |
| S16_read_shadow_renamed_reader | attack | gap | T1003.008 | missed | none | none | none | sensitive_file_access needs 1, got 0 | 0 | no | 0.004 | sensitive_file_access skips readers whose comm is on its expected-reader list, and the comm is the name of the file that was run, so a copy named sudo is suppressed. |
| S17_service_reads_passwd | attack | ordinary | T1003.008 | detected | sensitive_file_access 1 | none | none | - | 0 | no | 0.032 | - |
| S18_write_cron_file | attack | ordinary | T1053.003 | detected | persistence_write 1 | none | none | - | 0 | no | 0.004 | - |
| S19_append_bashrc | attack | ordinary | T1546.004 | detected | persistence_write 1 | none | none | - | 0 | no | 0.004 | - |
| S20_write_authorized_keys | attack | ordinary | T1098.004 | detected | persistence_write 1 | none | none | - | 0 | no | 0.004 | - |
| S21_write_systemd_unit | attack | ordinary | T1543.002 | detected | persistence_write 1 | none | none | - | 0 | no | 0.004 | - |
| S22_move_file_into_cron_dir | attack | gap | T1053.003 | missed | none | none | none | persistence_write needs 1, got 0 | 0 | no | 0.004 | persistence sees write opens only. A rename is not hooked, so a file moved into /etc/cron.d produces no write open. If the work directory and /etc/cron.d are on different filesystems, mv copies the file and the open of the destination would be seen. |
| S23_write_cron_file_renamed_writer | attack | gap | T1053.003 | missed | none | none | none | persistence_write needs 1, got 0 | 0 | no | 0.032 | persistence skips writers whose comm is on its expected-writer list, and the comm is the name of the file that was run, so a copy named dpkg is suppressed. |
| S24_regain_root_via_saved_uid | attack | ordinary | T1068 | detected | privilege_escalation 1 | none | none | - | 0 | no | 0.034 | - |
| S25_regain_root_renamed_helper | attack | gap | T1068 | missed | none | none | none | privilege_escalation needs 1, got 0 | 0 | no | 0.032 | privilege_escalation skips requests whose comm is on its expected-escalator list, and the comm is the name of the file that was run, so a symlink to python3 named sudo is suppressed. |
| S26_reverse_shell_style_connect | attack | ordinary | T1095 | detected | outbound_after_exec 1 | none | none | - | 0 | no | 0.016 | - |
| S27_delayed_connect | attack | gap | T1095 | missed | none | none | none | outbound_after_exec needs 1, got 0 | 0 | no | 70.025 | outbound_after_exec only counts a connect that comes within CONNECT_WINDOW_NS (60 s) of the latest exec of the process. A shell that sleeps longer than that before it connects is not seen. |
| S28_burst_of_spawns | attack | ordinary | T1059 | detected | rapid_spawn 1 | none | none | - | 0 | no | 0.064 | - |
| S29_slow_spawn_loop | attack | gap | T1059 | missed | none | none | none | rapid_spawn needs 1, got 0 | 0 | no | 24.084 | rapid_spawn counts distinct children of one parent inside a sliding window of WINDOW_NS (2 s). Thirty spawns spread over about 24 seconds never put the threshold's worth of children inside one window. |

A count above 0 in the column of alerts in the window without the marker means the scenario's evidence is not attributable by its marker; those alerts are listed below and are not scored.

## Scenarios not run

none

## Per technique (attack scenarios)

| technique | attacks | detected | missed | recall | ordinary | gap |
|---|---|---|---|---|---|---|
| T1003.008 | 3 | 2 | 1 | 2/3 (0.667) | 2/2 (1.000) | 0/1 (0.000) |
| T1053.003 | 3 | 1 | 2 | 1/3 (0.333) | 1/1 (1.000) | 0/2 (0.000) |
| T1059 | 7 | 4 | 3 | 4/7 (0.571) | 4/4 (1.000) | 0/3 (0.000) |
| T1059.004 | 3 | 2 | 1 | 2/3 (0.667) | 2/2 (1.000) | 0/1 (0.000) |
| T1068 | 2 | 1 | 1 | 1/2 (0.500) | 1/1 (1.000) | 0/1 (0.000) |
| T1095 | 2 | 1 | 1 | 1/2 (0.500) | 1/1 (1.000) | 0/1 (0.000) |
| T1098.004 | 1 | 1 | 0 | 1/1 (1.000) | 1/1 (1.000) | 0/0 (n/a) |
| T1105 | 4 | 3 | 1 | 3/4 (0.750) | 3/3 (1.000) | 0/1 (0.000) |
| T1543.002 | 1 | 1 | 0 | 1/1 (1.000) | 1/1 (1.000) | 0/0 (n/a) |
| T1546.004 | 1 | 1 | 0 | 1/1 (1.000) | 1/1 (1.000) | 0/0 (n/a) |
| T1552.004 | 1 | 1 | 0 | 1/1 (1.000) | 1/1 (1.000) | 0/0 (n/a) |

## Per detection

| detection | expected in | detected in | scenario recall | TP | FP | acceptable | precision (lenient) | precision (strict) |
|---|---|---|---|---|---|---|---|---|
| download_chmod_exec | 4 | 3 | 3/4 (0.750) | 3 | 0 | 0 | 3/3 (1.000) | 3/3 (1.000) |
| exec_from_tmp | 3 | 2 | 2/3 (0.667) | 2 | 0 | 0 | 2/2 (1.000) | 2/2 (1.000) |
| interpreter_chain | 2 | 1 | 1/2 (0.500) | 2 | 0 | 0 | 2/2 (1.000) | 2/2 (1.000) |
| outbound_after_exec | 2 | 1 | 1/2 (0.500) | 1 | 0 | 0 | 1/1 (1.000) | 1/1 (1.000) |
| persistence_write | 6 | 4 | 4/6 (0.667) | 4 | 0 | 0 | 4/4 (1.000) | 4/4 (1.000) |
| privilege_escalation | 2 | 1 | 1/2 (0.500) | 1 | 0 | 0 | 1/1 (1.000) | 1/1 (1.000) |
| rapid_spawn | 2 | 1 | 1/2 (0.500) | 1 | 0 | 0 | 1/1 (1.000) | 1/1 (1.000) |
| sensitive_file_access | 4 | 3 | 3/4 (0.750) | 3 | 0 | 0 | 3/3 (1.000) | 3/3 (1.000) |
| shell_from_service | 3 | 2 | 2/3 (0.667) | 2 | 0 | 0 | 2/2 (1.000) | 2/2 (1.000) |
| unusual_ancestry | 2 | 2 | 2/2 (1.000) | 2 | 0 | 0 | 2/2 (1.000) | 2/2 (1.000) |

Pooled recall (scenario level, secondary): 18/28 (0.643). Pooled precision (alert level): lenient 21/21 (1.000), strict 21/21 (1.000).
The pooled numbers mix the ordinary and the gap group, and the mix is a design choice and not a population, so they are secondary to the group tables above.

## Predicted versus actual

| scenario | predicted | actual | other alerts predicted | other alerts actual | status |
|---|---|---|---|---|---|
| S01_shell_from_service_after_loader | detected | detected | none | none | MATCH |
| S02_shell_from_service_before_loader | missed | missed | none | none | MATCH |
| S03_download_chmod_exec | detected | detected | none | none | MATCH |
| S04_exec_from_tmp_via_interpreter | missed | missed | none | none | MATCH |
| S05_benign_smoke | no alerts | no alerts | none | none | MATCH |
| S06_service_runs_python | detected | detected | none | none | MATCH |
| S07_service_shell_python | detected | detected | none | none | MATCH |
| S08_nested_inline_interpreters | detected | detected | none | none | MATCH |
| S09_nested_script_files | missed | missed | none | none | MATCH |
| S10_download_via_python | missed | missed | none | none | MATCH |
| S11_download_relative_path | detected | detected | none | none | MATCH |
| S12_run_from_shm | detected | detected | none | none | MATCH |
| S13_download_to_tmp_and_run | detected | detected | none | none | MATCH |
| S14_read_shadow | detected | detected | none | none | MATCH |
| S15_read_ssh_private_key | detected | detected | none | none | MATCH |
| S16_read_shadow_renamed_reader | missed | missed | none | none | MATCH |
| S17_service_reads_passwd | detected | detected | none | none | MATCH |
| S18_write_cron_file | detected | detected | none | none | MATCH |
| S19_append_bashrc | detected | detected | none | none | MATCH |
| S20_write_authorized_keys | detected | detected | none | none | MATCH |
| S21_write_systemd_unit | detected | detected | none | none | MATCH |
| S22_move_file_into_cron_dir | missed | missed | none | none | MATCH |
| S23_write_cron_file_renamed_writer | missed | missed | none | none | MATCH |
| S24_regain_root_via_saved_uid | detected | detected | none | none | MATCH |
| S25_regain_root_renamed_helper | missed | missed | none | none | MATCH |
| S26_reverse_shell_style_connect | detected | detected | none | none | MATCH |
| S27_delayed_connect | missed | missed | none | none | MATCH |
| S28_burst_of_spawns | detected | detected | none | none | MATCH |
| S29_slow_spawn_loop | missed | missed | none | none | MATCH |

Mismatches (listed, never scored): none.

## Benign runs

False positive alerts in benign scenarios: 0 over 20.072 s of benign run time; false positives per hour: 0.0.

## Latency (alert arrival at the harness minus the ts_ns of the triggering event)

Pipeline mode for these numbers: buffered: the stages run as in the live tests, with no python3 -u and no stdbuf. Negative values (clock disagreement): 0.

| alerts | n | p50 ms | p95 ms | max ms |
|---|---|---|---|---|
| all | 21 | 0.564 | 20.985 | 80.04 |
| true_positive | 21 | 0.564 | 20.985 | 80.04 |

## Resources

| process | samples | CPU % of one core, mean | CPU % p95 | max RSS kB | peak VmHWM kB |
|---|---|---|---|---|---|
| loader | 176 | 0.017 | 0.0 | 10960 | 14880 |
| normalizer | 176 | 0.017 | 0.0 | 12320 | 12320 |
| runner | 176 | 0.034 | 0.0 | 14080 | 14080 |

Events per second: 758 events over 175 s, mean 4.331, p95 15, peak 186.
Ring buffer drops: 0 lost events, 0 records dropped in total. Loader lines: loader: file_stats mode=exit openat_seen=7774 openat_blank=0 file_open_emitted=12 write_list_emitted=4 write_list_skipped_readonly=8

## bpf_stats (per BPF program, read while the loader was running)

| program | name bpftool returned | run count | total ns | mean ns per run | count from the run's own data | status |
|---|---|---|---|---|---|---|
| handle_connect | handle_connect | 12 | 98430 | 8202.5 | - | counts |
| handle_exec_attempt | handle_exec_attempt | 306 | 4683749 | 15306.4 | exec_attempt events 306 | counts |
| handle_exec_success | handle_exec_success | 213 | 2797409 | 13133.4 | exec_success events 213 | counts |
| handle_exit | handle_exit | 218 | 4090686 | 18764.6 | - | counts |
| handle_openat_exit | handle_openat_exit | 7762 | 2393859 | 308.4 | openat_seen 7774 | counts |
| handle_openat_save | handle_openat_save | 7762 | 1922633 | 247.7 | openat_seen 7774 | counts |
| handle_setgid | handle_setgid | n/a | n/a | n/a | - | no data from bpftool |
| handle_setresgid | handle_setresgid | 2 | 42614 | 21307.0 | - | counts |
| handle_setresuid | handle_setresuid | 4 | 32383 | 8095.8 | - | counts |
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
