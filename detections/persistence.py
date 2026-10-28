"""Detection persistence: write to persistence location, crontab, or systemctl command (installs one)"""
import os
import re
import sys
from collections import OrderedDict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  # noqa: E402
import attack_map  # noqa: E402
from exec_from_tmp import clean_path  # noqa: E402
from rapid_spawn import count  # noqa: E402
from shell_from_service import basename  # noqa: E402

FILE_DETECTION = "persistence_write"
COMMAND_DETECTION = "persistence_command"

#open flag bits that the Linux x86-64 values that telemetry/src/common.h names EVT_O_*
O_ACCMODE = 0o3
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100
O_TRUNC = 0o1000
O_APPEND = 0o2000

#persistence paths and their categories (editable): /etc/shadow, /etc/gshadow, /etc/sudoers and /etc/sudoers.d/ are left out because sensitive_file_access already alerts on a successful open of them
EXACT = {"/etc/ld.so.preload": "ld_preload", "/etc/crontab": "cron", "/etc/rc.local": "init",
         "/etc/profile": "shell_startup", "/etc/bash.bashrc": "shell_startup", "/etc/passwd": "accounts"}
PREFIX = (("/etc/ld.so.conf.d/", "ld_conf"), ("/etc/cron.d/", "cron"), ("/etc/cron.hourly/", "cron"),
          ("/etc/cron.daily/", "cron"), ("/etc/cron.weekly/", "cron"), ("/etc/cron.monthly/", "cron"),
          ("/var/spool/cron/", "cron"), ("/etc/systemd/system/", "systemd"),
          ("/usr/lib/systemd/system/", "systemd"), ("/lib/systemd/system/", "systemd"),
          ("/etc/init.d/", "init"), ("/etc/profile.d/", "shell_startup"), ("/etc/pam.d/", "pam"),
          ("/etc/update-motd.d/", "motd"))
HOME_EXACT = {".bashrc": "shell_startup", ".bash_profile": "shell_startup", ".bash_login": "shell_startup",
              ".profile": "shell_startup", ".bash_logout": "shell_startup", ".zshrc": "shell_startup",
              ".ssh/authorized_keys": "ssh_keys", ".ssh/authorized_keys2": "ssh_keys"}
HOME_PREFIX = ((".config/systemd/user/", "user_autostart"), (".config/autostart/", "user_autostart"))
HOME_RE = re.compile(r"/(?:root|home/[^/]+)/(.+)")

#programs that normally write to these locations (editable): matched on comm so a renamed binary is suppressed too while editors and shells are deliberately not listed
EXPECTED_WRITERS = ("dpkg", "apt", "apt-get", "aptitude", "rpm", "yum", "dnf", "unattended-upgr", "snapd",
                    "useradd", "usermod", "userdel", "groupadd", "groupmod", "adduser", "chpasswd", "passwd",
                    "chage", "vipw", "vigr", "update-rc.d", "systemctl", "systemd-sysusers",
                    "systemd-tmpfiles", "crontab", "cron")

#first guess: how many (process, path) pairs are remembered for dedup
MAX_SEEN_WRITES = 4096

#crontab options that install nothing (list, remove, dry run, help)... -u is the only one that takes a value
CRONTAB_NO_INSTALL = "lrnh"
CRONTAB_OTHER = "iesxV"
#systemctl options that take separate value taken from "systemctl --help" of systemd 255 on this machine; undocumented options and abbreviated long options are not known here currently
SYSTEMCTL_SHORT_VALUE = "HMtpPsno"
SYSTEMCTL_LONG_VALUE = ("--host", "--machine", "--type", "--state", "--property", "--job-mode", "--check-inhibitors",
                        "--kill-whom", "--kill-value", "--signal", "--what", "--legend", "--preset-mode", "--root",
                        "--image", "--image-policy", "--lines", "--output", "--boot-loader-menu",
                        "--boot-loader-entry", "--timestamp", "--drop-in", "--when")
SYSTEMCTL_INSTALL_VERBS = ("enable", "reenable", "link")


def category_of(path):
    if path in EXACT:
        return EXACT[path]
    for prefix, name in PREFIX:
        if path.startswith(prefix) and len(path) > len(prefix):
            return name
    m = HOME_RE.fullmatch(path)
    if m is not None:
        rest = m.group(1)
        if rest in HOME_EXACT:
            return HOME_EXACT[rest]
        for prefix, name in HOME_PREFIX:
            if rest.startswith(prefix) and len(rest) > len(prefix):
                return name
    return None


def wants_write(flags):
    return (flags & O_ACCMODE) in (O_WRONLY, O_RDWR) or bool(flags & (O_CREAT | O_TRUNC | O_APPEND))


def crontab_installs(args):
    """True if a crontab argument list installs a table (file name, "-" or -e) but False if not (None if it cant be parsed)"""
    installs = no_install = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            installs = installs or i + 1 < len(args)
            break
        if arg == "-" or not arg.startswith("-"):
            installs = True
        else:
            for j in range(1, len(arg)):
                ch = arg[j]
                if ch == "u":
                    if j == len(arg) - 1:
                        i += 1
                        if i >= len(args):
                            return None
                    break
                if ch == "e":
                    installs = True
                elif ch in CRONTAB_NO_INSTALL:
                    no_install = True
                elif ch not in CRONTAB_OTHER:
                    return None
        i += 1
    return installs and not no_install


def systemctl_verb(args):
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return args[i + 1] if i + 1 < len(args) else ""
        if arg.startswith("--"):
            if "=" not in arg and arg in SYSTEMCTL_LONG_VALUE:
                i += 1
                if i >= len(args):
                    return None
        elif arg.startswith("-") and arg != "-":
            for j in range(1, len(arg)):
                if arg[j] in SYSTEMCTL_SHORT_VALUE:
                    if j == len(arg) - 1:
                        i += 1
                        if i >= len(args):
                            return None
                    break
        else:
            return arg
        i += 1
    return ""


def command_alert(graph, event, ctx):
    exe = event.get("exe", event.get("filename"))
    if not isinstance(exe, str) or basename(exe) not in ("crontab", "systemctl"):
        return None
    argv = event.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        count(ctx, "persist_command_unparsed")
        return None
    args = argv[1:]
    if basename(exe) == "crontab":
        found = crontab_installs(args)
    else:
        verb = systemctl_verb(args)
        found = None if verb is None else verb in SYSTEMCTL_INSTALL_VERBS
    #argument list cut at capture limit might hide the form that matters
    if found is None or (found is False and event.get("argv_truncated") is True):
        count(ctx, "persist_command_unparsed")
        return None
    if not found:
        return None
    return alert.build_alert(graph, COMMAND_DETECTION, event, [event],
                             technique=attack_map.technique_for(COMMAND_DETECTION, basename(exe)))


def detect(graph, event, ctx):
    """
    return a persistence_write alert for a successful write open of a persistence path, or a persistence_command alert for an exec of crontab, or systemctl that installs something (otherwise None)
    a read-only open, an open with no flags or no ret, a failed open, an expected writer and a repeat by the same process on the same path are each counted with a persist_ name and do not alert
    """
    if not isinstance(event, dict):
        return None
    if event.get("type") == "exec_success":
        return command_alert(graph, event, ctx)
    if event.get("type") != "file_open":
        return None
    path = event.get("path")
    if not isinstance(path, str) or not path:
        count(ctx, "persist_no_path")
        return None
    if not path.startswith("/"):
        count(ctx, "persist_relative_path")
        return None
    path = clean_path(path)
    if category_of(path) is None:
        return None

    flags = event.get("flags")
    if type(flags) is not int:
        count(ctx, "persist_no_flags")
        return None
    if not wants_write(flags):
        count(ctx, "persist_read_only")
        return None
    ret = event.get("ret")
    if type(ret) is not int:
        count(ctx, "persist_no_return_value")
        return None
    if ret < 0:
        count(ctx, "persist_failed_open")
        return None
    if event.get("comm") in EXPECTED_WRITERS:
        count(ctx, "persist_expected_writer")
        return None

    key = alert.trigger_key(event)
    seen = ctx.setdefault("state", {}).setdefault("persistence", {"seen": OrderedDict()})["seen"]
    if key is not None:
        if (key, path) in seen:
            count(ctx, "persist_duplicate_write")
            return None
        seen[(key, path)] = True
        while len(seen) > MAX_SEEN_WRITES:
            seen.popitem(last=False)
    return alert.build_alert(graph, FILE_DETECTION, event, [event],
                             technique=attack_map.technique_for(FILE_DETECTION, category_of(path)))
