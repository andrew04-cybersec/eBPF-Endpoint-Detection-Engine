# Rescoring: what the two comparison files measure

The paper (Section 5) says that rescoring five saved runs with the old and the new harness code gave byte-identical score files. Two files in this folder look as if they contradict each other. They do not, because they compare different things.

## `oldcode-vs-newcode.txt` (the comparison the paper cites)

Both sides are fresh rescores of the same saved run data, made on the same day:

- OLD: the scorer from a snapshot of the code taken before the harness change (`baseline-src`, not published; the change itself is `harness-change.diff`).
- NEW: the scorer after the change (attribution of benign alerts by time window).

Result: `OLD==NEW` for `scores.json` and `report.md` in all five folders (10 lines). This supports the paper's statement. The check was made when the data existed and cannot be repeated from the published files.

## `rescore-result.txt` (what it compared)

It compares the NEW rescore with the `scores.json` and `report.md` that were saved in each run folder when the run was made. Those saved files were written by older versions of the scorer, so they are expected to differ in layout. Result: `DIFFERENT` for seven of the ten files and `IDENTICAL` for three. The seven are `scores.json` and `report.md` of the three early runs (six files) plus the `report.md` of the `evidence-eb-e2-run1` copy, which differs only in its title line (see the notes below). An analysis made while preparing this package (on the originals, before they were discarded) found:

| Run | `scores.json`: entries only in the rescore | entries only in the saved file | entries in both with a different value | `report.md` |
|---|---|---|---|---|
| 20261029-164811-eval | 95 | 0 | 1 (the number of `warnings`) | rescore has 79 lines the saved file lacks; the saved file has 20 lines the rescore lacks (an older, narrower scenario table) |
| 20261029-170342-eval | 95 | 0 | 1 (the number of `warnings`) | 79 and 20, same pattern |
| 20261030-212225-eval | 76 | 0 | 1 (the number of `warnings`) | 64 and 13, same pattern |
| 20261030-223359-eval | `IDENTICAL` | | | `IDENTICAL` |

The 95 and 76 added entries are fields that later versions of the scorer write (`groups`, `predictions`, `not_run_reasons`, extra `bpf_stats` fields). The extra `warnings` come from the rescore noticing that the live scenario folder had since changed (files edited after the run, scenarios S06 to S29 not part of the run). For two of the three runs a scenario-by-scenario check of `outcome`, `tp`, `fp`, `acceptable` and `unmet`, and of `alerts_total` and `pooled`, found no difference between the rescore and the saved file; the same check was not run on 20261029-170342-eval, whose structural comparison above shows the same pattern.

So the four `DIFFERENT` results record scorer evolution since the runs were made (added fields, a wider table, added warnings). They are not changes in any score the paper reports. This is an explanation from a comparison of the files, and it could not be repeated from the published files, because it needed the raw run data.

## Two further notes

- The "five saved runs" are four distinct runs plus a second copy of the original run: `evidence-eb-e2-run1` is byte-identical to `20261030-223359-eval` (the only difference is the title line of its `report.md`, which shows the folder name). The statement holds for four distinct runs.
- The early runs 20261029-164811, 20261029-170342 and 20261030-212225 have only their `scores.json` and `report.md` published (`../early-runs/`). Their raw data is not kept.
