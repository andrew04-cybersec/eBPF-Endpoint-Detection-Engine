#!/usr/bin/env python3
"""
pools the window-attributed benign runs of several scores.json files into one false positive rate (standard library only, read-only)
Usage: benign_rate.py SCORES_JSON [SCORES_JSON ...]
"""
import json
import sys

LABEL = "approximate; scripted workload, one machine, WSL2"


def read_runs(paths):
    """(rows, problems) with one row per window-attributed scenario found in files and also a file that cant be read or has no such scenario is a problem and not a row"""
    rows, problems = [], []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                scores = json.load(f)
        except (OSError, ValueError) as e:
            problems.append("%s: cannot be read (%s)" % (path, e))
            continue
        section = scores.get("window_attribution") if isinstance(scores, dict) else None
        found = section.get("scenarios") if isinstance(section, dict) else None
        if not isinstance(found, dict) or not found:
            problems.append("%s: no window-attributed scenario in this file" % path)
            continue
        for sid, r in sorted(found.items()):
            hours, fp = r.get("window_hours"), r.get("fp")
            if type(fp) is not int or not isinstance(hours, (int, float)) or hours <= 0:
                problems.append("%s: %s has no usable window_hours and fp" % (path, sid))
                continue
            rows.append({"path": path, "id": sid, "hours": float(hours), "fp": fp})
    return rows, problems


def pooled(rows):
    """total hours, total false positives, rate per hour, and the rule-of-three bound which exists only when total is zero"""
    hours = sum(r["hours"] for r in rows)
    fp = sum(r["fp"] for r in rows)
    return {"hours": hours, "fp": fp, "per_hour": fp / hours if hours else None,
            "rule_of_three": 3.0 / hours if fp == 0 and hours else None}


def report_lines(rows):
    total = pooled(rows)
    lines = ["runs: %d" % len(rows)]
    for r in rows:
        lines.append("  %s %s: %.4f hours, %d false positives, %.3f per hour" % (r["path"], r["id"], r["hours"], r["fp"], r["fp"] / r["hours"]))
    lines += ["total hours: %.4f" % total["hours"], "total false positives: %d" % total["fp"],
              "false positives per hour: %.3f" % total["per_hour"]]
    if total["rule_of_three"] is not None:
        lines.append("zero false positives: rule of three upper bound %.3f per hour (3 divided by %.4f hours); %s" % (total["rule_of_three"], total["hours"], LABEL))
    else:
        lines.append("rate: %s" % LABEL)
    return lines


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: benign_rate.py SCORES_JSON [SCORES_JSON ...]", file=sys.stderr)
        return 2
    rows, problems = read_runs(argv)
    for p in problems:
        print("problem: " + p, file=sys.stderr)
    if problems or not rows:
        return 2
    print("\n".join(report_lines(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
