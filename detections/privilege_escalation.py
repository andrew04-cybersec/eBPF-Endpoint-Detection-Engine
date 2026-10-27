"""Detection privilege_escalation: process that isnt root asks for uid 0 or process that wasnt root is later seen as root with no hooked request"""
import os
import sys
from collections import OrderedDict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  #noqa: E402
from download_chmod_exec import store_copy  #noqa: E402
from rapid_spawn import count  #noqa: E402

DETECTION_NAME = "privilege_escalation"

UID_REQUESTS = ("setuid", "setreuid", "setresuid")

#programs that ask for uid 0 as part of their normal job (editable); matched on comm so renamed binary is suppressed too
EXPECTED_ESCALATORS = ("sudo", "su", "pkexec", "doas", "sudoedit", "login", "sshd", "sshd-session", "passwd", "chsh",
                       "chfn", "newgrp", "gpasswd", "unix_chkpwd", "crontab", "at", "mount", "umount", "fusermount",
                       "fusermount3", "polkit-agent-he", "pam_timestamp_")

#first guess: how many processes are tracked before the oldest is forgotten
MAX_TRACKED_PROCESSES = 8192


def new_entry():
    return {"uid": None, "last": None, "request_seen": False, "expected_seen": False, "alerted": False}


def requests_root(event):
    """True if the requested ids include 0 and False if not (None if id list is missing or holds non-integer)"""
    ids = event.get("ids")
    if not isinstance(ids, list) or not ids or any(type(i) is not int for i in ids):
        return None
    return 0 in ids


def request_alert(graph, event, ctx, entry):
    root = requests_root(event)
    if root is None:
        count(ctx, "priv_no_ids")
        return None
    if not root:
        return None
    entry["request_seen"] = True
    uid = event.get("uid")
    if type(uid) is not int:
        count(ctx, "priv_no_uid")
        return None
    if uid == 0:
        count(ctx, "priv_already_root")
        return None
    if entry["alerted"]:
        count(ctx, "priv_already_alerted")
        return None
    if event.get("comm") in EXPECTED_ESCALATORS:
        count(ctx, "priv_expected_escalator")
        return None
    entry["alerted"] = True
    return alert.build_alert(graph, DETECTION_NAME, event, [event])


def transition_alert(graph, event, ctx, entry):
    if entry["alerted"]:
        count(ctx, "priv_transition_after_alert")
        return None
    if entry["request_seen"]:
        count(ctx, "priv_transition_after_request")
        return None
    if entry["expected_seen"]:
        count(ctx, "priv_transition_expected")
        return None
    entry["alerted"] = True
    return alert.build_alert(graph, DETECTION_NAME, event, [entry["last"], event])


def detect(graph, event, ctx):
    """
    return an alert (once per process key) for a setuid, setreuid, or setresuid request for uid 0 by caller with uid that isnt 0; unless its comm is in EXPECTED_ESCALATORS or for a process seen at uid 0 after earlier event at another uid with no request (otherwise None)
    uid in the events and hook is at syscall entry so a denied request looks like a granted one; a setuid binary or sudo's effective uid is invisible so every skipped case is counted with priv_ name
    """
    if not isinstance(event, dict):
        return None
    key = event.get("process_key")
    if not isinstance(key, str) or not key:
        count(ctx, "priv_no_key")
        return None
    procs = ctx.setdefault("state", {}).setdefault(DETECTION_NAME, {"procs": OrderedDict()})["procs"]
    entry = procs.get(key)
    if entry is None:
        entry = procs[key] = new_entry()
        while len(procs) > MAX_TRACKED_PROCESSES:
            procs.popitem(last=False)
            count(ctx, "priv_state_evicted")
    else:
        procs.move_to_end(key)

    uid = event.get("uid")
    known = type(uid) is int
    if event.get("comm") in EXPECTED_ESCALATORS:
        entry["expected_seen"] = True
    found = None
    if known and uid == 0 and type(entry["uid"]) is int and entry["uid"] != 0:
        found = transition_alert(graph, event, ctx, entry)
    elif event.get("type") == "priv_change" and event.get("syscall") in UID_REQUESTS:
        found = request_alert(graph, event, ctx, entry)
    if known:
        #last event at nonzero uid is kept as evidence for later transition to 0
        if uid != 0:
            entry["last"] = store_copy(event)
        entry["uid"] = uid
    return found
