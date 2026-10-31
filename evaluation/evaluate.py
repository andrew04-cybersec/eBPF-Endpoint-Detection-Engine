#!/usr/bin/env python3
"""
offline scorer and report generator of evaluation harness which reads a results folder and writes scores.json and report.md
Usage: evaluate.py RESULTS_DIR [--scenarios-dir DIR]   (no sudo; scoring the same folder twice gives byte-identical files)
"""
import argparse
import csv
import json
import os
import re
import sys

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, EVAL_DIR)
import scenario_lib  #noqa: E402

LIST_LIMIT = 40


def percentile(values, p):
    """nearest-rank percentile; sort ascending and take the value at index ceil(p/100 * n) - 1 (None when no values)"""
    n = len(values)
    if n == 0:
        return None
    rank = -(-p * n // 100)
    return sorted(values)[max(rank, 1) - 1]


def ratio(num, den):
    return {"num": num, "den": den, "value": round(num / den, 6) if den else None}


def rounded(value, places=3):
    return None if value is None else round(value, places)


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def read_env(path):
    env = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                key, sep, value = line.rstrip("\n").partition(": ")
                if sep:
                    env[key] = value
    except OSError:
        pass
    return env


def load_stamped(path):
    alerts, bad = [], 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                stamp, sep, text = line.rstrip("\n").partition("\t")
                try:
                    alert = json.loads(text)
                    arrival = int(stamp)
                except ValueError:
                    bad += 1
                    continue
                if not (sep and isinstance(alert, dict)):
                    bad += 1
                    continue
                alert["_arrival_ns"] = arrival
                alerts.append(alert)
    except OSError:
        pass
    return alerts, bad


def alert_strings(alert):
    """every text of an alert where a scenario marker can show up... the process command line, the command line and argv of each evidence event, and the command line of each ancestry entry"""
    out = []
    process = alert.get("process")
    if isinstance(process, dict):
        out.append(str(process.get("cmdline")))
    for ev in alert.get("evidence") if isinstance(alert.get("evidence"), list) else []:
        if isinstance(ev, dict):
            out.append(str(ev.get("cmdline")))
            if isinstance(ev.get("argv"), list):
                out.append(" ".join(str(a) for a in ev["argv"]))
    for entry in alert.get("ancestry") if isinstance(alert.get("ancestry"), list) else []:
        if isinstance(entry, dict):
            out.append(str(entry.get("cmdline")))
    return out


def has_marker(alert, marker):
    return any(marker in text for text in alert_strings(alert))


def brief(alert, scenario=None):
    process = alert.get("process") if isinstance(alert.get("process"), dict) else {}
    return {"alert_seq": alert.get("alert_seq"), "detection": alert.get("detection"), "ts_ns": alert.get("ts_ns"),
            "exe": process.get("exe"), "cmdline": str(process.get("cmdline"))[:100], "window": scenario}


def classify(scenario, alert):
    """tp, acceptable or fp for an alert attributed to the scenario; every alert of benign scenario is false positive"""
    name = alert.get("detection")
    if scenario["kind"] == "benign":
        return "fp"
    if name in [e["detection"] for e in scenario["expected"]]:
        return "tp"
    return "acceptable" if name in scenario["acceptable"] else "fp"


def latency_stats(values):
    return {"n": len(values), "p50_ms": rounded(percentile(values, 50)), "p95_ms": rounded(percentile(values, 95)),
            "max_ms": rounded(max(values)) if values else None}


def score_alerts(scenarios, windows, alerts):
    """attribute alerts to scenarios by window and marker and count them; returns: per scenario results, in-window list, outside list, and latencies"""
    ran = [s for s in scenarios if s["id"] in windows]
    per = {s["id"]: {"tp": {}, "acceptable": {}, "fp": {}, "alerts": 0} for s in ran}
    in_window, outside, latency_all, latency_tp = [], [], [], []
    by_id = {s["id"]: s for s in ran}
    order = sorted((sid for sid in windows if sid in by_id), key=lambda sid: (windows[sid]["start_ns"], sid))
    for alert in alerts:
        ts = alert.get("ts_ns")
        arrival = alert.get("_arrival_ns")
        lat = (arrival - ts) / 1e6 if type(ts) is int and type(arrival) is int else None
        if lat is not None:
            latency_all.append(lat)
        sid = next((i for i in order if type(ts) is int and windows[i]["start_ns"] <= ts <= windows[i]["end_ns"]), None)
        if sid is None:
            outside.append(brief(alert))
            continue
        scenario = by_id[sid]
        if not has_marker(alert, scenario["marker"]):
            in_window.append(brief(alert, sid))
            continue
        kind = classify(scenario, alert)
        bucket = per[sid][kind]
        bucket[alert.get("detection")] = bucket.get(alert.get("detection"), 0) + 1
        per[sid]["alerts"] += 1
        if kind == "tp" and lat is not None:
            latency_tp.append(lat)
    return per, in_window, outside, latency_all, latency_tp


def score(data):
    scenarios, windows = data["scenarios"], data["windows"]
    per, in_window, outside, lat_all, lat_tp = score_alerts(scenarios, windows, data["alerts"])
    out = {"scenarios": {}, "not_run": [], "not_run_reasons": {}, "warnings": list(data["warnings"])}
    skipped = data["windows_file"].get("skipped") if isinstance(data["windows_file"], dict) else None
    skipped = skipped if isinstance(skipped, dict) else {}
    unmarked = {}
    for a in in_window:
        unmarked[a["window"]] = unmarked.get(a["window"], 0) + 1
    groups = {"ordinary": [0, 0], "gap": [0, 0], "ungrouped": [0, 0]}
    techniques, detections = {}, {}
    pooled = {"attacks": 0, "detected": 0, "tp": 0, "fp": 0, "acceptable": 0}
    benign_alerts, benign_seconds = 0, 0.0
    names = set()
    for s in scenarios:
        names.update(e["detection"] for e in s["expected"])
        names.update(s["acceptable"])
    for p in per.values():
        for kind in ("tp", "acceptable", "fp"):
            names.update(p[kind])
    for name in names:
        detections[name] = {"expected": 0, "detected": 0, "tp": 0, "fp": 0, "acceptable": 0}
    for s in scenarios:
        sid = s["id"]
        if sid not in windows:
            out["not_run"].append(sid)
            out["not_run_reasons"][sid] = skipped.get(sid) or "no window was recorded (the run stopped before it started)"
            continue
        p = per[sid]
        w = windows[sid]
        seconds = (w["end_ns"] - w["start_ns"]) / 1e9
        rec = {"kind": s["kind"], "technique": s["technique"], "tp": p["tp"], "acceptable": p["acceptable"], "fp": p["fp"],
               "alerts_attributed": p["alerts"], "window_seconds": rounded(seconds), "timed_out": bool(w.get("timed_out")),
               "known_gap": s.get("known_gap"), "unmet": [], "group": s.get("group"), "in_window_without_marker": unmarked.get(sid, 0)}
        for kind in ("tp", "acceptable", "fp"):
            for name, n in p[kind].items():
                detections[name][kind] += n
                pooled[kind] += n
        if s["kind"] == "attack":
            for e in s["expected"]:
                got = p["tp"].get(e["detection"], 0)
                detections[e["detection"]]["expected"] += 1
                if got >= e["min_count"]:
                    detections[e["detection"]]["detected"] += 1
                else:
                    rec["unmet"].append({"detection": e["detection"], "min_count": e["min_count"], "got": got})
            rec["detected"] = not rec["unmet"]
            rec["outcome"] = "detected" if rec["detected"] else "missed"
            g = s.get("group") if s.get("group") in ("ordinary", "gap") else "ungrouped"
            groups[g][0] += 1
            groups[g][1] += 1 if rec["detected"] else 0
            t = techniques.setdefault(s["technique"], {"attacks": 0, "detected": 0, "by_group": {}})
            t["attacks"] += 1
            t["detected"] += 1 if rec["detected"] else 0
            bg = t["by_group"].setdefault(g, [0, 0])
            bg[0] += 1
            bg[1] += 1 if rec["detected"] else 0
            pooled["attacks"] += 1
            pooled["detected"] += 1 if rec["detected"] else 0
        else:
            rec["detected"] = None
            rec["outcome"] = "clean" if p["alerts"] == 0 else "false alerts"
            benign_alerts += p["alerts"]
            benign_seconds += seconds
        out["scenarios"][sid] = rec
    out["per_technique"] = {t: {"attacks": v["attacks"], "detected": v["detected"], "missed": v["attacks"] - v["detected"],
                                "recall": ratio(v["detected"], v["attacks"]),
                                "by_group": {g: ratio(v["by_group"].get(g, [0, 0])[1], v["by_group"].get(g, [0, 0])[0]) for g in ("ordinary", "gap")}}
                            for t, v in sorted(techniques.items())}
    out["groups"] = {g: {"scenarios": n, "detected": k, "missed": n - k, "recall": ratio(k, n)} for g, (n, k) in groups.items() if g != "ungrouped" or n}
    out["per_detection"] = {}
    for name, v in sorted(detections.items()):
        out["per_detection"][name] = dict(v, recall=ratio(v["detected"], v["expected"]),
                                          precision_lenient=ratio(v["tp"], v["tp"] + v["fp"]),
                                          precision_strict=ratio(v["tp"], v["tp"] + v["fp"] + v["acceptable"]))
    out["pooled"] = {"recall": ratio(pooled["detected"], pooled["attacks"]),
                     "precision_lenient": ratio(pooled["tp"], pooled["tp"] + pooled["fp"]),
                     "precision_strict": ratio(pooled["tp"], pooled["tp"] + pooled["fp"] + pooled["acceptable"]),
                     "tp": pooled["tp"], "fp": pooled["fp"], "acceptable": pooled["acceptable"]}
    out["benign"] = {"alerts": benign_alerts, "seconds": rounded(benign_seconds),
                     "fp_per_hour": rounded(benign_alerts / (benign_seconds / 3600.0), 3) if benign_seconds else None}
    out["latency"] = {"all": latency_stats(lat_all), "true_positive": latency_stats(lat_tp),
                      "negative": sum(1 for v in lat_all if v < 0), "mode": data["env"].get("mode")}
    out["unattributed_in_window"] = in_window
    out["unattributed_outside_windows"] = outside
    out["alerts_total"] = len(data["alerts"])
    out["bad_alert_lines"] = data["bad_alert_lines"]
    out["clock_check"] = data["windows_file"].get("clock_check")
    out["resources"] = resource_stats(data)
    out["bpf_stats"] = bpf_stats(data["bpf"], cross_checks(data))
    out["label_set_sha256"] = data["hashes"].get("set") if isinstance(data["hashes"], dict) else None
    out["predictions"] = compare_predictions(data["predictions"], out)
    return out


def compare_predictions(predictions, scored):
    """predicted against actual for every scenario and a mismatch is listed and never scored; None is returned for folder with no predictions"""
    if not isinstance(predictions, dict) or not isinstance(predictions.get("predictions"), dict):
        return None
    rows, mismatches = [], []
    for sid in sorted(set(predictions["predictions"]) | set(scored["scenarios"]) | set(scored["not_run"])):
        p = predictions["predictions"].get(sid)
        r = scored["scenarios"].get(sid)
        if r is None:
            rows.append({"id": sid, "predicted": p.get("predicted_outcome") if p else None, "actual": "not run", "status": "not run",
                         "other_predicted": sorted(p.get("predicted_other_alerts") or []) if p else [], "other_actual": []})
            continue
        actual = r["outcome"] if r["kind"] == "attack" else ("no alerts" if r["outcome"] == "clean" else "false alerts")
        other = sorted(set(r["acceptable"]) | set(r["fp"]))
        if p is None:
            rows.append({"id": sid, "predicted": None, "actual": actual, "status": "no prediction", "other_predicted": [], "other_actual": other})
            continue
        predicted_other = sorted(p.get("predicted_other_alerts") or [])
        same = p.get("predicted_outcome") == actual and predicted_other == other
        rows.append({"id": sid, "predicted": p.get("predicted_outcome"), "actual": actual, "status": "MATCH" if same else "MISMATCH",
                     "other_predicted": predicted_other, "other_actual": other})
        if not same:
            mismatches.append(sid)
    return {"rows": rows, "mismatches": mismatches, "label_set_sha256": predictions.get("label_set_sha256")}


def resource_stats(data):
    """CPU and memory per process from resources.csv, events per second from the raw events and the ring buffer drops"""
    result = {"processes": {}, "events": None, "drops": None}
    clk = data["env"].get("clk_tck")
    clk = int(clk) if clk and clk.isdigit() else None
    rows = {}
    for row in data["resources"]:
        rows.setdefault(row["role"], []).append(row)
    for role in sorted(rows):
        series = sorted(rows[role], key=lambda r: r["elapsed_ns"])
        cpu = []
        for a, b in zip(series, series[1:]):
            dt = (b["elapsed_ns"] - a["elapsed_ns"]) / 1e9
            if clk and dt > 0:
                cpu.append(((b["ticks"] - a["ticks"]) / clk) / dt * 100.0)
        rss = [r["rss"] for r in series if r["rss"] is not None]
        hwm = [r["hwm"] for r in series if r["hwm"] is not None]
        result["processes"][role] = {"samples": len(series), "cpu_percent_mean": rounded(sum(cpu) / len(cpu)) if cpu else None,
                                     "cpu_percent_p95": rounded(percentile(cpu, 95)), "max_rss_kb": max(rss) if rss else None,
                                     "peak_vmhwm_kb": max(hwm) if hwm else None}
    stamps = data["event_ts"]
    if stamps:
        first = min(stamps)
        bins = (max(stamps) - first) // 1000000000 + 1
        counts = [0] * bins
        for t in stamps:
            counts[(t - first) // 1000000000] += 1
        result["events"] = {"n": len(stamps), "seconds": bins, "mean_per_s": rounded(len(stamps) / bins),
                            "p95_per_s": percentile(counts, 95), "peak_per_s": max(counts)}
    result["drops"] = {"lost_events": data["lost_events"], "dropped_records": data["lost_dropped"],
                       "loader_lines": data["loader_lines"]}
    return result


def cross_checks(data):
    """counts of run's own data that program's run count can be set beside; exec events for two exec programs and openat_seen from loader's stats line for openat programs"""
    out = {}
    types = data["event_types"]
    if types:
        out["handle_exec_attempt"] = {"what": "exec_attempt events", "count": types.get("exec_attempt", 0)}
        out["handle_exec_success"] = {"what": "exec_success events", "count": types.get("exec_success", 0)}
    if data["openat_seen"] is not None:
        for name in ("handle_openat_entry", "handle_openat_save", "handle_openat_exit"):
            out[name] = {"what": "openat_seen", "count": data["openat_seen"]}
    return out


def bpf_stats(raw, cross=None):
    cross = cross or {}
    if not isinstance(raw, dict):
        return {"available": False, "reason": "bpf_stats.json is missing", "programs": [], "not_found": None, "ambiguous": [],
                "selected_by": None, "raw_names": []}
    programs = []
    for p in raw.get("programs") or []:
        cnt, ns = p.get("run_cnt"), p.get("run_time_ns")
        mean = round(ns / cnt, 1) if type(cnt) is int and type(ns) is int and cnt > 0 else None
        status = p.get("status") or ("counts" if type(cnt) is int else "no data from bpftool")
        programs.append({"name": p.get("name"), "kernel_name": p.get("kernel_name") or p.get("name"), "run_cnt": cnt, "run_time_ns": ns,
                         "mean_ns_per_run": mean, "status": status, "own_data": cross.get(p.get("name"))})
    programs.sort(key=lambda p: str(p["name"]))
    not_found = raw.get("not_found")
    return {"available": bool(raw.get("available")), "reason": raw.get("reason"), "programs": programs,
            "not_found": sorted(not_found) if isinstance(not_found, list) else None,
            "ambiguous": raw.get("ambiguous") or [], "selected_by": raw.get("selected_by"),
            "raw_names": sorted(raw.get("raw_names_selected") or [])}


def load_resources(path):
    rows = []
    try:
        with open(path, newline="", encoding="ascii") as f:
            for r in csv.DictReader(f):
                try:
                    rows.append({"elapsed_ns": int(r["elapsed_ns"]), "role": r["role"], "ticks": int(r["utime_ticks"]) + int(r["stime_ticks"]),
                                 "rss": int(r["vmrss_kb"]) if r["vmrss_kb"] else None, "hwm": int(r["vmhwm_kb"]) if r["vmhwm_kb"] else None})
                except (KeyError, ValueError):
                    continue
    except OSError:
        pass
    return rows


def load_events(path):
    stamps, lost, dropped, types = [], 0, 0, {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(ev, dict):
                    continue
                if type(ev.get("ts_ns")) is int:
                    stamps.append(ev["ts_ns"])
                if isinstance(ev.get("type"), str):
                    types[ev["type"]] = types.get(ev["type"], 0) + 1
                if ev.get("type") == "lost":
                    lost += 1
                    dropped += ev["dropped"] if type(ev.get("dropped")) is int else 0
    except OSError:
        pass
    return stamps, lost, dropped, types


def load_results(folder, scenarios_dir, predictions_path=None):
    """read a results folder and the scenarios come from the snapshot taken at run time and also a warning is made for every live file that no longer matches it"""
    warnings = []
    hashes = read_json(os.path.join(folder, "label_hashes.json"), {})
    windows_file = read_json(os.path.join(folder, "scenario_windows.json"), {})
    snap_dir = os.path.join(folder, "scenarios_snapshot")
    scenarios = []
    if os.path.isdir(snap_dir):
        for name in sorted(os.listdir(snap_dir)):
            sc = read_json(os.path.join(snap_dir, name))
            if isinstance(sc, dict) and "id" in sc:
                scenarios.append(sc)
    else:
        warnings.append("WARNING: the folder has no scenarios_snapshot, so nothing can be scored")
    recorded = hashes.get("scenarios", {}) if isinstance(hashes, dict) else {}
    for sc in scenarios:
        path = os.path.join(snap_dir, sc["id"] + ".json")
        if recorded.get(sc["id"]) != scenario_lib.sha256_file(path):
            warnings.append("WARNING: the snapshot of %s does not match the hash recorded at run time" % sc["id"])
    if os.path.isdir(scenarios_dir):
        for sid, digest in sorted(recorded.items()):
            live = os.path.join(scenarios_dir, sid, "scenario.json")
            if not os.path.isfile(live):
                warnings.append("WARNING: the live scenario file for %s is gone; the snapshot is used" % sid)
            elif scenario_lib.sha256_file(live) != digest:
                warnings.append("WARNING: the live scenario file for %s was changed after the run; the snapshot is used" % sid)
        for sid in sorted(os.listdir(scenarios_dir)):
            if os.path.isdir(os.path.join(scenarios_dir, sid)) and sid not in recorded:
                warnings.append("WARNING: the live scenario %s was not part of this run" % sid)
    else:
        warnings.append("WARNING: the live scenario directory was not found, so the label hashes could not be compared")
    predictions = read_json(os.path.join(folder, "predictions.json"))
    recorded_p = hashes.get("predictions_sha256") if isinstance(hashes, dict) else None
    if recorded_p:
        copy = os.path.join(folder, "predictions.json")
        if not os.path.isfile(copy) or scenario_lib.sha256_file(copy) != recorded_p:
            warnings.append("WARNING: the predictions in this folder do not match the hash recorded at run time")
        live_p = predictions_path or os.path.join(os.path.dirname(os.path.normpath(scenarios_dir)), "predictions.json")
        if not os.path.isfile(live_p):
            warnings.append("WARNING: the live predictions file is gone; the copy in the folder is used")
        elif scenario_lib.sha256_file(live_p) != recorded_p:
            warnings.append("WARNING: the live predictions file was changed after the run; the copy in the folder is used")
        written_for = predictions.get("label_set_sha256") if isinstance(predictions, dict) else None
        if isinstance(written_for, str) and isinstance(hashes.get("set"), str) and written_for != hashes["set"]:
            warnings.append("WARNING: the predictions were written against a different label set than the one of this run")
    alerts, bad = load_stamped(os.path.join(folder, "alerts.stamped.tsv"))
    stamps, lost, dropped, types = load_events(os.path.join(folder, "events.jsonl"))
    loader_lines, openat_seen = [], None
    try:
        with open(os.path.join(folder, "loader.stderr"), encoding="utf-8", errors="replace") as f:
            loader_lines = [l.rstrip("\n") for l in f if "file_stats" in l or "lost" in l or "drop" in l]
    except OSError:
        pass
    for l in loader_lines:
        m = re.search(r"file_stats .*openat_seen=(\d+)", l)
        if m:
            openat_seen = int(m.group(1))
    return {"scenarios": scenarios, "windows": windows_file.get("scenarios", {}), "windows_file": windows_file, "hashes": hashes,
            "alerts": alerts, "bad_alert_lines": bad, "env": read_env(os.path.join(folder, "env.txt")),
            "resources": load_resources(os.path.join(folder, "resources.csv")), "event_ts": stamps, "lost_events": lost,
            "lost_dropped": dropped, "loader_lines": loader_lines, "bpf": read_json(os.path.join(folder, "bpf_stats.json")),
            "event_types": types, "openat_seen": openat_seen, "predictions": predictions, "warnings": warnings}


def fmt_ratio(r):
    return "%d/%d (%s)" % (r["num"], r["den"], "n/a" if r["value"] is None else "%.3f" % r["value"])


def fmt(value):
    return "n/a" if value is None else str(value)


def table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return lines


def counts(d):
    return ", ".join("%s %d" % kv for kv in sorted(d.items())) or "none"


def render_report(folder_name, scores, data):
    s = scores
    lines = ["# Evaluation report: " + folder_name, ""]
    lines += s["warnings"] + [""] if s["warnings"] else []
    env = data["env"]
    lines += ["Pipeline mode: %s. Label set hash: %s." % (fmt(env.get("mode")), fmt(s["label_set_sha256"])),
              "Alerts read: %d (%d unreadable lines). Scenarios not run: %s." % (s["alerts_total"], s["bad_alert_lines"], ", ".join(s["not_run"]) or "none"), ""]
    cc = s["clock_check"]
    lines += ["Clock check: %s." % ("not recorded" if not cc else ("passed" if cc.get("passed") else "FAILED"))
              + ("" if not cc else " Largest distance outside the bracket: %s ns." % fmt(cc.get("max_skew_ns"))), ""]
    g = s["groups"]
    lines += ["## Headline: attack scenarios by group", ""]
    lines += table(["group", "scenarios", "detected", "missed", "recall"],
                   [(name, v["scenarios"], v["detected"], v["missed"], fmt_ratio(v["recall"])) for name, v in g.items()]) + [""]
    lines += ["The ordinary group was written by the same person who read the detection rules, so its recall is a best case and not a detection rate. The gap group is built to miss: its scenarios exercise documented gaps, so a miss there is an expected result and not a harness error. The two groups are never added into one score here.", ""]
    lines += ["## Scenario outcomes", ""]
    rows = []
    for sid, r in sorted(s["scenarios"].items()):
        unmet = "; ".join("%s needs %d, got %d" % (u["detection"], u["min_count"], u["got"]) for u in r["unmet"]) or "-"
        rows.append((sid, r["kind"], fmt(r["group"]), fmt(r["technique"]), r["outcome"], counts(r["tp"]), counts(r["acceptable"]), counts(r["fp"]),
                     unmet, r["in_window_without_marker"], "yes" if r["timed_out"] else "no", fmt(r["window_seconds"]), r["known_gap"] or "-"))
    lines += table(["scenario", "kind", "group", "technique", "outcome", "true positive alerts", "acceptable alerts", "false positive alerts",
                    "unmet expectations", "alerts in window without the marker", "timed out", "window s", "known gap"], rows) + [""]
    lines += ["A count above 0 in the column of alerts in the window without the marker means the scenario's evidence is not attributable by its marker; those alerts are listed below and are not scored.", ""]
    lines += ["## Scenarios not run", ""]
    if s["not_run"]:
        lines += ["- %s: %s" % (sid, s["not_run_reasons"].get(sid, "no reason recorded")) for sid in s["not_run"]] + [""]
    else:
        lines += ["none", ""]
    lines += ["## Per technique (attack scenarios)", ""]
    lines += table(["technique", "attacks", "detected", "missed", "recall", "ordinary", "gap"],
                   [(t, v["attacks"], v["detected"], v["missed"], fmt_ratio(v["recall"]), fmt_ratio(v["by_group"]["ordinary"]), fmt_ratio(v["by_group"]["gap"]))
                    for t, v in s["per_technique"].items()]) + [""]
    lines += ["## Per detection", ""]
    lines += table(["detection", "expected in", "detected in", "scenario recall", "TP", "FP", "acceptable", "precision (lenient)", "precision (strict)"],
                   [(n, v["expected"], v["detected"], fmt_ratio(v["recall"]), v["tp"], v["fp"], v["acceptable"],
                     fmt_ratio(v["precision_lenient"]), fmt_ratio(v["precision_strict"])) for n, v in s["per_detection"].items()]) + [""]
    p = s["pooled"]
    lines += ["Pooled recall (scenario level, secondary): %s. Pooled precision (alert level): lenient %s, strict %s." % (
        fmt_ratio(p["recall"]), fmt_ratio(p["precision_lenient"]), fmt_ratio(p["precision_strict"])),
              "The pooled numbers mix the ordinary and the gap group, and the mix is a design choice and not a population, so they are secondary to the group tables above.", ""]
    pr = s["predictions"]
    lines += ["## Predicted versus actual", ""]
    if pr is None:
        lines += ["No predictions file was saved with this folder.", ""]
    else:
        lines += table(["scenario", "predicted", "actual", "other alerts predicted", "other alerts actual", "status"],
                       [(x["id"], fmt(x["predicted"]), x["actual"], ", ".join(x["other_predicted"]) or "none", ", ".join(x["other_actual"]) or "none", x["status"])
                        for x in pr["rows"]]) + [""]
        lines += ["Mismatches (listed, never scored): %s." % (", ".join(pr["mismatches"]) or "none"), ""]
    b = s["benign"]
    lines += ["## Benign runs", "",
              "False positive alerts in benign scenarios: %d over %s s of benign run time; false positives per hour: %s." % (
                  b["alerts"], fmt(b["seconds"]), fmt(b["fp_per_hour"])), ""]
    lat = s["latency"]
    lines += ["## Latency (alert arrival at the harness minus the ts_ns of the triggering event)", "",
              "Pipeline mode for these numbers: %s. Negative values (clock disagreement): %d." % (fmt(lat["mode"]), lat["negative"]), ""]
    lines += table(["alerts", "n", "p50 ms", "p95 ms", "max ms"],
                   [(k, lat[k]["n"], fmt(lat[k]["p50_ms"]), fmt(lat[k]["p95_ms"]), fmt(lat[k]["max_ms"])) for k in ("all", "true_positive")]) + [""]
    r = s["resources"]
    lines += ["## Resources", ""]
    if r["processes"]:
        lines += table(["process", "samples", "CPU % of one core, mean", "CPU % p95", "max RSS kB", "peak VmHWM kB"],
                       [(role, v["samples"], fmt(v["cpu_percent_mean"]), fmt(v["cpu_percent_p95"]), fmt(v["max_rss_kb"]), fmt(v["peak_vmhwm_kb"]))
                        for role, v in r["processes"].items()]) + [""]
    else:
        lines += ["No resource samples were recorded.", ""]
    e = r["events"]
    lines += ["Events per second: " + ("not recorded." if not e else "%d events over %d s, mean %s, p95 %s, peak %s." % (
        e["n"], e["seconds"], e["mean_per_s"], e["p95_per_s"], e["peak_per_s"]))]
    d = r["drops"]
    lines += ["Ring buffer drops: %d lost events, %d records dropped in total. Loader lines: %s" % (
        d["lost_events"], d["dropped_records"], " / ".join(d["loader_lines"]) or "none"), ""]
    lines += ["## bpf_stats (per BPF program, read while the loader was running)", ""]
    bs = s["bpf_stats"]
    if bs["programs"]:
        lines += table(["program", "name bpftool returned", "run count", "total ns", "mean ns per run", "count from the run's own data", "status"],
                       [(q["name"], q["kernel_name"], fmt(q["run_cnt"]), fmt(q["run_time_ns"]), fmt(q["mean_ns_per_run"]),
                         "%s %d" % (q["own_data"]["what"], q["own_data"]["count"]) if q["own_data"] else "-", q["status"])
                        for q in bs["programs"]]) + [""]
        lines += ["Programs were selected by: %s." % fmt(bs["selected_by"]), ""]
    else:
        lines += ["Not available: %s." % fmt(bs["reason"]), ""]
    nf = bs["not_found"]
    lines += ["Expected programs not found in the bpftool output: %s." % ("not recorded in this folder" if nf is None else (", ".join(nf) or "none"))]
    for a in bs["ambiguous"]:
        lines += ["Ambiguous, not assigned to a program: bpftool name %s could be %s%s." % (
            a.get("kernel_name"), " or ".join(a.get("candidates") or []), " (" + a["reason"] + ")" if a.get("reason") else "")]
    lines += ["", "The own-data column is the number of exec_attempt or exec_success events in the raw events file, or openat_seen from the loader's stats line. It is printed for comparison and a difference is not an error: bpf_stats was enabled slightly after the loader attached, so the first firings are missing from the run counts.",
              "handle_exit fires once per thread exit and handle_connect once per connect call of any address family, while events are emitted per process and only for IPv4 and IPv6, and the privilege programs fire once per call, so their run counts are shown without a comparison and exceed the events by design.",
              "A status of 'no data from bpftool' means the program was listed but bpftool gave no run_cnt or run_time_ns for it. The bpftool man page does not say that these are left out for a program that has not run, so this is not read as zero runs.", ""]
    lines += ["## Unattributed alerts (listed, not scored)", "", "Inside a scenario window without that scenario's marker: %d." % len(s["unattributed_in_window"])]
    lines += ["- %s %s ts_ns %s window %s exe %s: %s" % (a["alert_seq"], a["detection"], a["ts_ns"], a["window"], a["exe"], a["cmdline"])
              for a in s["unattributed_in_window"][:LIST_LIMIT]]
    lines += ["", "Outside every scenario window: %d." % len(s["unattributed_outside_windows"])]
    lines += ["- %s %s ts_ns %s exe %s: %s" % (a["alert_seq"], a["detection"], a["ts_ns"], a["exe"], a["cmdline"])
              for a in s["unattributed_outside_windows"][:LIST_LIMIT]]
    lines += ["", "## What these numbers do not mean", "",
              "- A handful of scenarios is a demonstration and not a statistical estimate. A ratio such as 3/4 says what happened in these runs only, and a recall of 1 over a few scenarios is not a detection rate.",
              "- Labels follow the threat model, so a miss on a scenario with a documented gap is an expected result of the telemetry and the rules, not a harness error.",
              "- Precision here depends on which scenarios were run. The benign scenarios are short and are not a baseline of normal use, so false positives per hour is not a rate for a real machine.",
              "- Latency is the time from the triggering event (kernel monotonic clock) to the harness reading the alert line, through the loader, normalizer and runner. It is only as valid as the clock check, and it excludes the time before the event.",
              "- CPU, memory and bpf_stats were measured while the pipeline ran with the sampler and the harness itself running; their cost is not subtracted. The bpf_stats numbers cover all programs while bpf_stats was enabled, which adds overhead of its own.",
              "- A service started before the loader is a placeholder node with no name, so detections that need its name cannot judge it. These misses are a property of the design and not of the scoring.", ""]
    return "\n".join(lines)


def write_outputs(folder, scores, report):
    with open(os.path.join(folder, "scores.json"), "w", encoding="ascii") as f:
        f.write(json.dumps(scores, sort_keys=True, indent=1, ensure_ascii=True, allow_nan=False) + "\n")
    with open(os.path.join(folder, "report.md"), "w", encoding="ascii") as f:
        f.write(report)


def score_folder(folder, scenarios_dir=None):
    scenarios_dir = os.path.join(EVAL_DIR, "scenarios") if scenarios_dir is None else scenarios_dir
    data = load_results(folder, scenarios_dir)
    scores = score(data)
    report = render_report(os.path.basename(os.path.normpath(folder)), scores, data)
    write_outputs(folder, scores, report)
    return scores, report


def main(argv=None):
    ap = argparse.ArgumentParser(description="Score an evaluation results folder.")
    ap.add_argument("results_dir")
    ap.add_argument("--scenarios-dir")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.results_dir):
        print("evaluate: %s is not a directory" % args.results_dir, file=sys.stderr)
        return 2
    scores, _ = score_folder(args.results_dir, args.scenarios_dir)
    for w in scores["warnings"]:
        print(w, file=sys.stderr)
    print("scored %d scenarios; wrote scores.json and report.md in %s" % (len(scores["scenarios"]), args.results_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
