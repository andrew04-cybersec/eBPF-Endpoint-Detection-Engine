# Predictions for the independent scenario set

The labels come from an isolated author's threat models and the technique mapping, **written before any run of S30 to S37**. `predicted_outcome` is "detected" for every scenario because that is the threat-model label, not a forecast informed by detector logic. Any miss is a finding, never a failure to fix. Results are reported separately from S01 to S29 and the near-miss set, and are never pooled. Nothing in this file is a result of a run, and no prediction is changed after a run.

Label set the predictions were written against (sha256 of the scenario files): `9b3bcb6d47ddf6a1aad681e31522a2a929b980b71b28b122f561a2bc6e3eebcb` (to be computed with `set_hash()` in WSL and filled in before the first run)

## Label principles

- The scenarios were written by an author who never saw the detectors. Each scenario carries the author's technique and threat model.
- Expected and acceptable lists were derived only from the technique mapping. A detection whose mapped technique equals the scenario technique is expected. A detection mapped to the parent technique of the same family is acceptable. No list was derived from a reading of detection logic.
- Any alert from a detection that is in neither list counts as a false positive.
- Eight scenarios are a demonstration and not a statistical estimate. The group is `independent` and is never added into the ordinary or gap rows.

## Predictions

predicted_outcome is detected (every expected entry met) for every scenario, as a threat-model label. Other alerts are left empty everywhere, because no forecast of other alerts was made. The harness copies `predictions.json` into the results folder, records its sha256, and prints predicted against actual in the report.

| Scenario | Group | Technique | Expected | Predicted outcome | Other alerts predicted | Label source | Assumptions |
|---|---|---|---|---|---|---|---|
| S30_service_shell | independent | T1059.004 | shell_from_service 1 | detected | none | Technique mapping: T1059.004 to shell_from_service. Acceptable: interpreter_chain, unusual_ancestry, exec_from_tmp, rapid_spawn (parent technique T1059). | a background worker stands in for the compromised service, with no network listener |
| S31_payload_transfer | independent | T1105 | download_chmod_exec 1 | detected | none | Technique mapping: T1105 to download_chmod_exec. | a local copy of a prepared file stands in for a completed transfer, with no network communication |
| S32_password_material | independent | T1003.008 | sensitive_file_access 1 | detected | none | Technique mapping: T1003.008 to sensitive_file_access. | synthetic passwd and shadow files in the work directory stand in for the real databases; the account record names the fake home /home/evt_eval_s32, a mechanical change made while staging |
| S33_private_key_harvest | independent | T1552.004 | sensitive_file_access 1 | detected | none | Technique mapping: T1552.004 to sensitive_file_access. | an invalid synthetic key in a fake home stands in for a private key |
| S34_raw_command_channel | independent | T1095 | outbound_after_exec 1 | detected | none | Technique mapping: T1095 to outbound_after_exec. | a local Unix domain socket stands in for a non-application-layer channel, with no network traffic; the author calls this a limited approximation |
| S35_cron_persistence | independent | T1053.003 | persistence_command 1, persistence_write 1 | detected | none | Technique mapping: T1053.003 to persistence_command and persistence_write; both exact matches are expected. | a cron definition file is written and the cron daemon is not required to run |
| S36_shell_startup | independent | T1546.004 | persistence_write 1 | detected | none | Technique mapping: T1546.004 to persistence_write. | the startup file is written in an isolated fake home |
| S37_dynamic_linker_hijack | independent | T1574.006 | persistence_write 1 | detected | none | Technique mapping: T1574.006 to persistence_write. | LD_PRELOAD is scoped to one test process and no system linker file is changed |

## Notes

- S35 expects two detections because the staging rule took every exact match of the technique in the mapping. The scenario counts as detected only when both expected entries are met. This is a labeling choice for the owner to review, and it is not a forecast.
- S32 had one mechanical change at staging: the home path in the synthetic account record was renamed to /home/evt_eval_s32 and the location home was declared. A lint finding on that line is open at the time of writing, so the set will not start until it is resolved.
