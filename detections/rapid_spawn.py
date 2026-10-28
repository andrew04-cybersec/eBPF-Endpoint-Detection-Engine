"""Detection rapid_spawn: one parent starts many distinct child processes inside a short window"""
import os
import sys
from collections import OrderedDict, deque

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  # noqa: E402
import attack_map  # noqa: E402
from shell_from_service import unevaluable  # noqa: E402

DETECTION_NAME = "rapid_spawn"

#first guess: children of one parent are needed for burst and the window they must fall in; how many parents are tracked and how many children are stored per parent
SPAWN_THRESHOLD = 25
WINDOW_NS = 2 * 1000000000
MAX_TRACKED_PARENTS = 4096
MAX_ENTRIES_PER_PARENT = 256


def count(ctx, name):
    ctx["counts"][name] = ctx["counts"].get(name, 0) + 1


def new_parent():
    #the evidence deque holds references to events and is as long as the alert module keeps so therefore an alert never has the evidence that would be counted as dropped
    return {"window": deque(), "keys": set(), "evidence": deque(maxlen=alert.MAX_EVIDENCE_EVENTS),
            "armed": True, "last_ts": None}


def detect(graph, event, ctx):
    """
    return alert on exec_success which makes the number of distinct children of one parent inside the window reach SPAWN_THRESHOLD (otherwise None); it'll stays quiet for that parent while the count stays at (or above) the threshold and is armed again once a count below it is seen (burst gives one alert)
    child is counted once per parent even if execs again in place and also a timestamp that goes backwards is counted as out_of_order and is treated as the latest time seen in which it keeps the window sorted
    """
    if not isinstance(event, dict) or event.get("type") != "exec_success":
        return None
    ts = event.get("ts_ns")
    if type(ts) is not int:
        unevaluable(ctx, "no_timestamp")
        return None
    child = alert.trigger_key(event)
    node = graph.nodes.get(child)
    if node is None:
        unevaluable(ctx, "not_in_graph")
        return None
    parent_key = node.parent_key
    if parent_key is None:
        unevaluable(ctx, "no_parent")
        return None

    parents = ctx.setdefault("state", {}).setdefault(DETECTION_NAME, {"parents": OrderedDict()})["parents"]
    entry = parents.get(parent_key)
    if entry is None:
        entry = parents[parent_key] = new_parent()
        while len(parents) > MAX_TRACKED_PARENTS:
            parents.popitem(last=False)
    else:
        parents.move_to_end(parent_key)

    if entry["last_ts"] is not None and ts < entry["last_ts"]:
        count(ctx, "out_of_order")
        ts = entry["last_ts"]
    entry["last_ts"] = ts

    window, keys, recent = entry["window"], entry["keys"], entry["evidence"]
    while window and window[0][1] < ts - WINDOW_NS:
        keys.discard(window.popleft()[0])
    while recent and recent[0][0] < ts - WINDOW_NS:
        recent.popleft()
    if child not in keys:
        if len(window) >= MAX_ENTRIES_PER_PARENT:
            keys.discard(window.popleft()[0])
        window.append((child, ts))
        keys.add(child)
        recent.append((ts, event))

    if len(window) < SPAWN_THRESHOLD:
        entry["armed"] = True
        return None
    if not entry["armed"]:
        return None
    entry["armed"] = False
    return alert.build_alert(graph, DETECTION_NAME, event, [e for _, e in recent], technique=attack_map.technique_for(DETECTION_NAME))
