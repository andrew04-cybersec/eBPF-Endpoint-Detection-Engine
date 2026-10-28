"""Detection outbound_after_exec: process that looks sus makes outbound connection after execution"""
import ipaddress
import os
import sys
from collections import OrderedDict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  # noqa: E402
import attack_map  # noqa: E402
from exec_from_tmp import clean_path, under_suspect_dir  # noqa: E402
from rapid_spawn import count  # noqa: E402
from shell_from_service import basename, unevaluable  # noqa: E402
from unusual_ancestry import watched  # noqa: E402

DETECTION_NAME = "outbound_after_exec"

#private; link-local and unique-local destinations are alertable on purpose (lateral movement and a live test can run without internet)... set to True to exclude
EXCLUDE_PRIVATE_RANGES = False

#first guess: how long after exec a connect still counts and how many connections are remembered for dedup, lastly how many exec events are kept for evidence
CONNECT_WINDOW_NS = 60 * 1000000000
MAX_SEEN_CONNECTIONS = 4096
MAX_TRACKED_EXECS = 4096


def not_alertable(ip):
    """
    return True for loopback (including IPv4-mapped loopback) and unspecified addresses, and then also for private ranges when EXCLUDE_PRIVATE_RANGES is set
    IPv4-mapped IPv6 address is judged as the IPv4 address inside it
    """
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified:
        return True
    return EXCLUDE_PRIVATE_RANGES and (ip.is_private or ip.is_link_local)


def suspect_exe(exe):
    if exe.startswith("/") and under_suspect_dir(clean_path(exe)):
        return True
    return watched(basename(exe)) is not None


def detect(graph, event, ctx):
    """
    return an alert for net_connect to alertable address by a sus process in which the latest successful exec was at most CONNECT_WINDOW_NS earlier, once per (process, address, port); (otherwise None)
    the program is judged by exe of exec history and not by comm which is cut to 15 characters; the record is connect attempt only so a refused connection will therefore look like a success
    """
    if not isinstance(event, dict):
        return None
    state = ctx.setdefault("state", {}).setdefault(DETECTION_NAME, {"seen": OrderedDict(), "execs": OrderedDict()})
    if event.get("type") == "exec_success":
        key = alert.trigger_key(event)
        if key is not None:
            state["execs"][key] = event
            state["execs"].move_to_end(key)
            while len(state["execs"]) > MAX_TRACKED_EXECS:
                state["execs"].popitem(last=False)
        return None
    if event.get("type") != "net_connect":
        return None

    addr = event.get("remote_addr")
    try:
        ip = ipaddress.ip_address(addr) if isinstance(addr, str) else None
    except ValueError:
        ip = None
    if ip is None:
        unevaluable(ctx, "net_bad_address")
        return None
    if not_alertable(ip):
        count(ctx, "connect_loopback")
        return None

    key = alert.trigger_key(event)
    node = graph.nodes.get(key)
    if node is None:
        unevaluable(ctx, "net_not_in_graph")
        return None
    done = [x for x in node.execs if isinstance(x, dict) and x.get("failed") is False
            and isinstance(x.get("exe"), str) and type(x.get("ts_ns")) is int]
    ts = event.get("ts_ns")
    if not done:
        unevaluable(ctx, "net_no_exec_seen")
        return None
    if type(ts) is not int:
        unevaluable(ctx, "net_no_timestamp")
        return None
    latest = done[-1]
    if not suspect_exe(latest["exe"]):
        count(ctx, "connect_not_suspect_process")
        return None
    gap = ts - latest["ts_ns"]
    if gap < 0:
        count(ctx, "out_of_order")
        return None
    if gap > CONNECT_WINDOW_NS:
        count(ctx, "connect_outside_window")
        return None

    triple = (key, str(ip), event.get("remote_port"))
    if triple in state["seen"]:
        count(ctx, "duplicate_connect")
        return None
    state["seen"][triple] = True
    while len(state["seen"]) > MAX_SEEN_CONNECTIONS:
        state["seen"].popitem(last=False)

    held = state["execs"].get(key)
    evidence = [held, event] if held is not None and held.get("ts_ns") == latest["ts_ns"] else [event]
    return alert.build_alert(graph, DETECTION_NAME, event, evidence, technique=attack_map.technique_for(DETECTION_NAME))
