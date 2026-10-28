"""Detection exec_from_tmp: program is executed from a world-writable temporary directory"""
import os
import posixpath
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  # noqa: E402
import attack_map  # noqa: E402
from shell_from_service import unevaluable  # noqa: E402

DETECTION_NAME = "exec_from_tmp"

#directories where executed file is sus (editable); installers and build tools also run files from them so currently there is no allow list in v1
SUSPECT_DIRS = ("/tmp", "/var/tmp", "/dev/shm")


def clean_path(filename):
    """
    lexically collapse repeated slashes and resolve "." and ".." in an absolute path.
    posixpath.normpath keeps exactly two leading slashes but Linux treats //tmp/x as /tmp/x, so they are collapsed here too
    """
    path = posixpath.normpath(filename)
    if path.startswith("//"):
        path = "/" + path.lstrip("/")
    return path


def under_suspect_dir(path):
    return any(path.startswith(d + "/") for d in SUSPECT_DIRS)


def detect(graph, event, ctx):
    """
    return alert for exec_success in which an absolute filename is under a sus directory (otherwise None); a relative, missing, unreadable, or truncated filename that isnt already under a sus directory cant be judged so its counted as unevaluable
    truncated filename is judged by the prefix that was kept so a later ".." in the cut part could hide a different path
    """
    if not isinstance(event, dict) or event.get("type") != "exec_success":
        return None
    filename = event.get("filename")
    if event.get("user_read_failed") is True:
        unevaluable(ctx, "read_failed")
        return None
    if not isinstance(filename, str) or not filename:
        unevaluable(ctx, "no_filename")
        return None
    if not filename.startswith("/"):
        unevaluable(ctx, "relative_path")
        return None
    if not under_suspect_dir(clean_path(filename)):
        if event.get("filename_truncated") is True:
            unevaluable(ctx, "truncated")
        return None

    attempt = ctx["attempts"].get(alert.trigger_key(event))
    evidence = [attempt, event] if attempt is not None else [event]
    return alert.build_alert(graph, DETECTION_NAME, event, evidence, technique=attack_map.technique_for(DETECTION_NAME))
