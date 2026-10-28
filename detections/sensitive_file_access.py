"""Detection sensitive_file_access: successful open of credential file by a program that isnt expected to read it"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  # noqa: E402
import attack_map  # noqa: E402
from exec_from_tmp import clean_path  # noqa: E402
from shell_from_service import is_service, unevaluable  # noqa: E402

DETECTION_NAME = "sensitive_file_access"

#tier 1 paths (editable): these alert unless the reader is expected; private keys are files directly under .ssh of /root or /home/<user> that are not public keys or ssh bookkeeping files
TIER1_EXACT = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers")
TIER1_PREFIX = ("/etc/sudoers.d/",)
SSH_KEY_DIR = re.compile(r"/(?:root|home/[^/]+)/\.ssh/([^/]+)")
SSH_NOT_PRIVATE = ("known_hosts", "known_hosts.old", "config", "authorized_keys", "authorized_keys2")

#tier 2 path (editable): read by almost every program so it alerts only when the reader runs below a service
TIER2_EXACT = ("/etc/passwd",)

#programs that read the tier 1 files as part of their normal job (editable); this is a name list so a renamed binary is going to be suppressed too
EXPECTED_READERS = ("sshd", "sudo", "su", "login", "passwd", "chpasswd", "chage", "useradd", "usermod", "userdel",
                    "groupadd", "groupmod", "vipw", "vigr", "pwck", "grpck", "unix_chkpwd", "unix_update", "newgrp",
                    "gpasswd", "ssh", "ssh-agent", "ssh-add", "ssh-keygen", "scp", "sftp")


def tier_of(path):
    if path in TIER1_EXACT or any(path.startswith(p) and len(path) > len(p) for p in TIER1_PREFIX):
        return 1
    m = SSH_KEY_DIR.fullmatch(path)
    if m is not None and not m.group(1).endswith(".pub") and m.group(1) not in SSH_NOT_PRIVATE:
        return 1
    if path in TIER2_EXACT:
        return 2
    return None


def detect(graph, event, ctx):
    """
    return an alert for successful file_open of a sensitive path (otherwise None); a failed open (ret below 0) or an open with no ret is counted and doesnt alert (and a tier 1 open by a program in EXPECTED_READERS is counted as expected_reader)
    for /etc/passwd the reader itself isnt ever counted but rather only the nodes above it; if no service is found and the chain doesnt end at root then the answer is unknown and therefore counted
    """
    if not isinstance(event, dict) or event.get("type") != "file_open":
        return None
    path = event.get("path")
    if not isinstance(path, str) or not path:
        unevaluable(ctx, "no_path")
        return None
    if not path.startswith("/"):
        unevaluable(ctx, "relative_path")
        return None
    tier = tier_of(clean_path(path))
    if tier is None:
        return None

    ret = event.get("ret")
    if type(ret) is not int:
        unevaluable(ctx, "no_return_value")
        return None
    if ret < 0:
        unevaluable(ctx, "failed_open")
        return None

    if tier == 1:
        if event.get("comm") in EXPECTED_READERS:
            unevaluable(ctx, "expected_reader")
            return None
    else:
        key = alert.trigger_key(event)
        if key not in graph.nodes:
            unevaluable(ctx, "not_in_graph")
            return None
        result = graph.ancestry(key)
        above = [graph.nodes[k] for k in result["chain"][1:] if k in graph.nodes]
        if not any(isinstance(n.comm, str) and is_service(n.comm) for n in above):
            if result["stop"] != "root":
                unevaluable(ctx, "ancestry_incomplete")
            return None
    technique = attack_map.technique_for(DETECTION_NAME, attack_map.sensitive_category(clean_path(path)))
    return alert.build_alert(graph, DETECTION_NAME, event, [event], technique=technique)
