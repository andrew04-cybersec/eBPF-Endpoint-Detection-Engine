# Predictions for the near-miss benign set

These predictions were written from the threat model and the rule constants alone, **written before any run of N01 to N08**. A mismatch between predicted and actual is a finding to report, not a failure to fix. Nothing in this file is a result of a run, and no prediction is changed after a run.

Label set the predictions were written against (sha256 of the scenario files): `f419657963f3ea5eb19d2327d62e7bf86e0013becea4fdfb974c47ebe9327fcc`

## How the set is scored and reported

- The set is run as `sudo python3 evaluation/run_eval.py --scenarios-dir evaluation/benign/nearmiss/scenarios`. Each scenario has its own window and its own marker, and alerts are attributed by marker as in the frozen set.
- Every scenario is benign, so every alert in it counts as a false positive. A scenario predicted to alert is written as `false alerts` with the detection in the other-alerts column. The schema is not bent: `expected` stays empty for all eight.
- The result is reported as k of 8 scenarios alerted, with each alert listed. It is never reported as a rate, and it is never pooled with the everyday set. The false positives per hour line in the run report divides by seconds of window time, which is meaningless for this set and must be ignored.
- Eight scenarios are a demonstration of where benign activity meets a rule, and not a statistical estimate.

## Predictions

predicted_outcome is no alerts, or false alerts for a benign scenario that is predicted to alert. Other alerts are the detections predicted to fire. The harness copies `predictions.json` into the results folder, records its sha256, and prints predicted against actual in the report.

| Scenario | Predicted outcome | Other alerts predicted | Rule it comes from | Assumptions |
|---|---|---|---|---|
| N01_install_local_prefix | no alerts | none | Nothing runs from /tmp, /var/tmp or /dev/shm, no persistence path is written, no sensitive path is read, and interpreter_chain needs two families. | everything happens under the work directory under /opt; the installed tool is a script that starts with #!/bin/sh |
| N02_install_staged_in_tmp | false alerts | exec_from_tmp | exec_from_tmp (T1059, weak fit): an exec_success whose absolute filename is under /tmp. Benign activity that resembles the rule target. | /tmp is not mounted noexec; the copy is run by its absolute path |
| N03_parallel_build_j200 | false alerts | rapid_spawn | rapid_spawn: SPAWN_THRESHOLD 25 distinct children of one parent inside 2 seconds, and make -j200 over 400 trivial targets starts far more. | make starts the recipes as direct children; no event is lost, which must be checked in the lost events of the run and not assumed |
| N04_sed_inplace_bashrc | no alerts | none | The kernel filter skips a read-only open of .bashrc, and a temporary file with another name is not on the write-intent list. | UNSURE, needs a live run: GNU sed writes a temporary file and renames it; rename is not hooked |
| N05_append_bashrc_redirect | false alerts | persistence_write | persistence_write (T1546.004): a write open of .bashrc by a comm that is not in EXPECTED_WRITERS. S19 was detected on the same rule. | the redirect is done by the action's bash |
| N06_sshkeygen_fake_home | no alerts | none | sensitive_file_access skips a tier 1 open by a comm in EXPECTED_READERS, and ssh-keygen is in that list. | the comm is ssh-keygen; the fake home name stays within 31 characters |
| N07_cat_ssh_key_nonlisted_reader | false alerts | sensitive_file_access | sensitive_file_access (T1552.004), tier 1: a private key under .ssh read by a reader that is not expected. The contrast case to N06. | the key is created in setup.sh before the pipeline starts; cat is not in EXPECTED_READERS |
| N08_root_cat_shadow | false alerts | sensitive_file_access | sensitive_file_access (T1003.008), tier 1: /etc/shadow opened by a reader that is not expected. S14 was detected on the same rule. | the action runs as root |

## Notes

- N03 starts hundreds of processes at once, so event loss is possible. It is checked in the lost events and the ring buffer drops of the run, and not assumed.
- N04 is the only prediction marked as unsure. It rests on the order of syscalls of GNU sed, which was not checked.
