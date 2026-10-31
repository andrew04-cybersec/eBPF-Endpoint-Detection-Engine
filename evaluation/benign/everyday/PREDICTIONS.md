# Predictions for the everyday benign set

This prediction was written from the detection rules alone, **written before any run of E01**. Nothing in this file is a result of a run, and no prediction is changed after a run.

Label set the prediction was written against (sha256 of the scenario files): `70385b2d0099eba187df859d889e5e171b0da6651c4f030a875a86fdc9c22960`

## How the set is scored

- The set is run as `sudo python3 evaluation/run_eval.py --scenarios-dir evaluation/benign/everyday/scenarios --seed N`, three times with three different seeds, each for a 60 minute window.
- Attribution is by window and needs no marker. An alert inside the window counts as a false positive unless the process that triggered it is one that run_eval.py started itself (a harness alert, listed and not counted). An alert outside the window is machine noise (listed and not counted).
- No alert is suppressed, excused or reclassified after a run. The workload is frozen once it is committed and is not tuned to avoid alerts.
- The result is a rate from a scripted workload on one machine, so it is approximate. With zero false positives, the rule of three gives an approximate upper bound of 3 divided by the hours.

## Prediction

predicted_outcome is no alerts, because this is a benign scenario. The harness copies `predictions.json` into the results folder, records its sha256, and prints predicted against actual in the report.

| Scenario | Group | Technique | Expected | Predicted outcome | Other alerts predicted | Rule or gap it comes from | Assumptions |
|---|---|---|---|---|---|---|---|
| E01_everyday_workload | none | none | none | no alerts | none | No detection fires on ordinary developer commands: exec_from_tmp needs an exec from /tmp, /var/tmp or /dev/shm, the service-based detections need a service-named ancestor, download_chmod_exec needs curl or wget, outbound_after_exec needs a non-loopback connect, persistence needs a write to a persistence path, sensitive_file_access needs a sensitive path, privilege_escalation needs a uid change, rapid_spawn needs 25 children of one parent inside 2 seconds, and interpreter_chain needs three consecutive shells or interpreters of two families with inline code. | the driver runs under timeout, so the action's bash -c is not part of any interpreter chain; all work stays under the work directory and TMPDIR points inside it; no command uses the network, sudo or a sensitive path on purpose |

## Pre-registered risks (notes, not expectations)

These are written down before the first run so that none of them can be explained away afterward. Each one that happens is a false positive of the set.

- make -j4 builds a project of 30 source files and starts about 31 recipe shells from one parent. That may reach the rapid_spawn threshold of 25 children inside 2 seconds.
- Build tools may exec from a temporary directory. TMPDIR is set inside the work directory, so exec_from_tmp should not see /tmp, but this is not measured.
- The driver runs under timeout, then make and sh. The action's own bash -c is not a harness process, and interpreter_chain reads the whole structure, so an alert there is possible.
- ls, ps, tar and git look up user names through the password file. The kernel filter reports those opens, and sensitive_file_access alerts on that file only when a service-named process is above the reader.
