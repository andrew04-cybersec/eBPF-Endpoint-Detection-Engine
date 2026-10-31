"""scenario files for the evaluation harness; loading, validation, the script lint and the label hashes (standard library only)"""
import hashlib
import json
import os
import re
import shlex
import sys

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(EVAL_DIR)
sys.path.insert(0, os.path.join(ROOT, "detections"))
import attack_map  #noqa: E402

DETECTION_NAMES = tuple(sorted(set(attack_map.DETECTIONS) | set(attack_map.CATEGORY_TABLES)))

REQUIRED = ("id", "title", "kind", "technique", "threat_model", "phase", "marker", "expected", "acceptable",
            "timeout_seconds", "known_gap", "notes", "group")
OPTIONAL = ("requires", "tmp_staging", "locations", "needs", "attribution")
GROUPS = ("ordinary", "gap", "independent")
#how the scorer attributes alerts to a scenario; scenario without the key is attributed by marker and window is for the long benign workload
ATTRIBUTIONS = ("marker", "window")
LOCATIONS = ("tmp", "shm", "cron", "systemd", "home")
NEEDS = ("non_loopback_ipv4",)
KINDS = ("attack", "benign")
PHASES = ("after_loader", "before_loader")
ID_PATTERN = re.compile(r"[A-Za-z0-9_]+")
MARKER_PATTERN = re.compile(r"EVT_EVAL_[A-Z0-9_]+")
SCRIPTS = ("setup", "action", "teardown")

WORK_PREFIX = "/opt/evt_eval_"
TMP_PREFIX = "/tmp/evt_eval_"


DEFAULT_BASES = {"work": "/opt", "tmp": "/tmp", "shm": "/dev/shm", "cron": "/etc/cron.d", "systemd": "/etc/systemd/system", "home": "/home"}


def scenario_env(sid, bases=None, address=None):
    """the environment every script of scenario gets; its own work directory under /opt and own staging directory under /tmp"""
    b = dict(DEFAULT_BASES)
    b.update(bases or {})
    low = sid.lower()
    # the kernel filter reads only HOME_USER_SCAN bytes of /home/<name>/, so the fake home keeps just the scenario number
    env = {"EVT_EVAL_ID": sid,
           "EVT_EVAL_WORK": "%s/evt_eval_%s" % (b["work"], low), "EVT_EVAL_TMP": "%s/evt_eval_%s" % (b["tmp"], low),
           "EVT_EVAL_SHM": "%s/evt_eval_%s" % (b["shm"], low), "EVT_EVAL_HOME": "%s/evt_eval_%s" % (b["home"], low.split("_")[0]),
           "EVT_EVAL_CRON_FILE": "%s/evt_eval_%s" % (b["cron"], low), "EVT_EVAL_UNIT": "%s/evt_eval_%s.service" % (b["systemd"], low),
           "EVT_EVAL_TMP_BASE": b["tmp"], "EVT_EVAL_SHM_BASE": b["shm"], "EVT_EVAL_CRON_DIR": b["cron"],
           "EVT_EVAL_SYSTEMD_DIR": b["systemd"], "EVT_EVAL_HOME_BASE": b["home"]}
    if address:
        env["EVT_EVAL_NONLOOPBACK_IPV4"] = address
    return env


def scenario_paths(sid, bases=None):
    """every path a scenario may create from its environment variables as the directories and two single files"""
    env = scenario_env(sid, bases)
    return [env[k] for k in ("EVT_EVAL_WORK", "EVT_EVAL_TMP", "EVT_EVAL_SHM", "EVT_EVAL_HOME", "EVT_EVAL_CRON_FILE", "EVT_EVAL_UNIT")]


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    with open(path, "rb") as f:
        return sha256_bytes(f.read())


def set_hash(hashes):
    text = "".join("%s:%s\n" % (sid, hashes[sid]) for sid in sorted(hashes))
    return sha256_bytes(text.encode("ascii"))


PROTECTED = re.compile(r"/(etc|usr|bin|lib|lib64|sbin|root|home|tmp|opt|var|boot|sys|proc|dev/shm)(/|$)")
ALWAYS_DENIED = ("shutdown", "reboot", "poweroff", "halt", "iptables", "ip6tables", "nft")
COPYABLE = ("sudo", "su", "pkexec", "doas", "systemctl", "crontab")
WRITE_ALL = ("tee", "touch", "mkdir", "rmdir", "chmod", "chown", "truncate", "mkfifo", "mknod", "mv")
WRITE_LAST = ("cp", "ln", "install")
OPERATORS = (";", "&&", "||", "|", "&", "(", ")")
NAME = r"evt_eval_[a-z0-9_]+"


def var(name):
    return r"\$\{?%s\}?" % name


ALLOWED = {
    "work": [var("EVT_EVAL_WORK") + r"(/.*)?", r"/opt/" + NAME + r"(/.*)?"],
    "tmp": [var("EVT_EVAL_TMP") + r"(/.*)?", r"/tmp/" + NAME + r"(/.*)?"],
    "shm": [var("EVT_EVAL_SHM") + r"(/.*)?", r"/dev/shm/" + NAME + r"(/.*)?", var("EVT_EVAL_SHM_BASE") + "/" + NAME + r"(/.*)?"],
    "cron": [var("EVT_EVAL_CRON_FILE"), r"/etc/cron\.d/" + NAME, var("EVT_EVAL_CRON_DIR") + "/" + NAME],
    "systemd": [var("EVT_EVAL_UNIT"), r"/etc/systemd/system/" + NAME + r"\.service", var("EVT_EVAL_SYSTEMD_DIR") + "/" + NAME + r"\.service"],
    "home": [var("EVT_EVAL_HOME") + r"(/.*)?", r"/home/" + NAME + r"(/.*)?", var("EVT_EVAL_HOME_BASE") + "/" + NAME + r"(/.*)?"],
}
DIRECTORY_LOCATIONS = ("work", "tmp", "shm", "home")
MENTIONS = {"tmp": r"/tmp|EVT_EVAL_TMP", "shm": r"/dev/shm|EVT_EVAL_SHM", "cron": r"/etc/cron|EVT_EVAL_CRON",
            "systemd": r"/etc/systemd|EVT_EVAL_UNIT|EVT_EVAL_SYSTEMD", "home": r"/home\b|EVT_EVAL_HOME"}
LITERAL_WORD = re.compile(r"(?:/tmp|/dev/shm|/etc/cron|/etc/systemd|/home)[^\s'\"<>|;&()]*")
WORK_COPY = re.compile(var("EVT_EVAL_WORK") + r"/([^/]+)|/opt/" + NAME + r"/([^/]+)")


def strip_comment(line):
    return re.sub(r"(^|\s)#.*$", "", line)


def tokens_of(line):
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return line.split()


def segments(tokens):
    seg = []
    for t in tokens:
        if t in OPERATORS:
            if seg:
                yield seg
            seg = []
        else:
            seg.append(t)
    if seg:
        yield seg


def location_of(path):
    """(location name, allowed) for a path that fully matches one of the allowed patterns otherwise... (None, False)"""
    for loc, patterns in ALLOWED.items():
        if any(re.fullmatch(p, path) for p in patterns):
            return loc, True
    return None, False


def traversal(path):
    """reason a path is refused for containing a parent directory step or glob (or None)"""
    if ".." in path.split("/"):
        return "write to %s has path traversal" % path
    if any(c in path for c in "*?["):
        return "write to %s has a glob" % path
    return None


def check_target(path, declared):
    """reason a write target is refused (or None); target is accepted if its an allowed pattern of the work directory or of a declared location, or if it is none of the protected places"""
    bad = traversal(path)
    if bad:
        return bad
    loc, ok = location_of(path)
    if loc is not None:
        return None if loc == "work" or loc in declared else "write to %s uses %s without declaring it" % (path, loc)
    if PROTECTED.match(path):
        return "write to %s is not allowed" % path
    return None


def created_copies(text):
    """names of the files the script creates under the work directory with cp or ln"""
    names = set()
    for raw in text.splitlines():
        for seg in segments(tokens_of(strip_comment(raw))):
            if os.path.basename(seg[0]) in ("cp", "ln"):
                args = [a for a in seg[1:] if not a.startswith("-")]
                m = WORK_COPY.fullmatch(args[-1]) if args else None
                if m:
                    names.add(m.group(1) or m.group(2))
    return names


def lint_script(text, allow_tmp=False, locations=(), created=None):
    """list of (line number, rule) for everything in a scenario script the safety net refuses; its a safety net against mistakes and not a sandbox: a script that builds a command from pieces or also runs another file is not understood by it"""
    problems = []
    declared = set(locations) | ({"tmp"} if allow_tmp else set())
    created = created_copies(text) if created is None else created
    for number, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw)
        if not line.strip():
            continue
        if re.search(r"\bdd\b[^\n;|&]*\bof=", line):
            problems.append((number, "dd with of= is not allowed"))
        if "ld.so.preload" in line:
            problems.append((number, "/etc/ld.so.preload is not allowed"))
        for loc, pattern in MENTIONS.items():
            if re.search(pattern, line) and loc not in declared:
                problems.append((number, "uses %s without declaring it" % loc))
        for m in LITERAL_WORD.finditer(line):
            word = m.group(0)
            loc, ok = location_of(word)
            if loc is None or loc == "work":
                problems.append((number, "%s is outside the allowed patterns" % word))
        tokens = tokens_of(line)
        for token in tokens:
            for piece in re.split(r"[\s;&|()<>]+", token):
                piece = piece.strip("'\"")
                base = os.path.basename(piece)
                if not base:
                    continue
                if base in ALWAYS_DENIED or base.startswith("mkfs"):
                    problems.append((number, "command %s is not allowed" % base))
                elif base in COPYABLE:
                    m = WORK_COPY.fullmatch(piece)
                    if not (m and (m.group(1) or m.group(2)) == base and base in created):
                        problems.append((number, "command %s is not allowed" % base))
        for seg in segments(tokens):
            name, args = os.path.basename(seg[0]), seg[1:]
            targets = [a for a in args if not a.startswith("-") and a not in (">", ">>", "<", "<<")]
            writes = []
            if name == "rm":
                recursive = any(a.startswith("--recursive") or (a.startswith("-") and not a.startswith("--") and re.search("[rR]", a)) for a in args)
                for t in targets:
                    loc, ok = location_of(t)
                    if recursive and traversal(t):
                        problems.append((number, traversal(t)))
                    elif recursive and not (loc in DIRECTORY_LOCATIONS and t.rstrip("/") == t and (loc == "work" or loc in declared)):
                        problems.append((number, "rm -r of %s is outside the work directory variable" % t))
                    elif not recursive:
                        writes.append(t)
            elif name in WRITE_ALL:
                writes = targets
            elif name in WRITE_LAST and targets:
                writes = targets[-1:]
            for prev, t in zip(seg, seg[1:]):
                if prev in (">", ">>") or re.fullmatch(r"\d?>>?", prev):
                    writes.append(t)
            for t in writes:
                reason = check_target(t, declared)
                if reason:
                    problems.append((number, reason))
    return problems


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load_scenarios(directory):
    scenarios, problems = [], []
    if not os.path.isdir(directory):
        return [], ["scenario directory %s does not exist" % directory]
    for entry in sorted(os.listdir(directory)):
        folder = os.path.join(directory, entry)
        if not os.path.isdir(folder):
            continue
        path = os.path.join(folder, "scenario.json")
        if not os.path.isfile(path):
            problems.append("%s: scenario.json is missing" % entry)
            continue
        try:
            with open(path, "rb") as f:
                raw = f.read()
            sc = json.loads(raw.decode("utf-8"))
        except (ValueError, OSError) as e:
            problems.append("%s: scenario.json cannot be read (%s)" % (entry, e))
            continue
        if not isinstance(sc, dict):
            problems.append("%s: scenario.json is not an object" % entry)
            continue
        sc["_dir"] = folder
        sc["_sha256"] = sha256_bytes(raw)
        sc["_scripts"] = {k: (os.path.join(folder, k + ".sh") if os.path.isfile(os.path.join(folder, k + ".sh")) else None)
                          for k in SCRIPTS}
        scenarios.append(sc)
    scenarios.sort(key=lambda s: str(s.get("id")))
    problems += validate(scenarios)
    return scenarios, problems


def check_entries(label, name, entries, need_count):
    problems = []
    if not isinstance(entries, list):
        return ["%s: %s must be a list" % (label, name)]
    for e in entries:
        if need_count:
            if not (isinstance(e, dict) and set(e) == {"detection", "min_count"}):
                problems.append("%s: each %s entry needs exactly detection and min_count" % (label, name))
                continue
            det, count = e["detection"], e["min_count"]
            if type(count) is not int or count < 1:
                problems.append("%s: min_count of %s must be an integer of at least 1" % (label, det))
        else:
            det = e
        if det not in DETECTION_NAMES:
            problems.append("%s: unknown detection name %r in %s" % (label, det, name))
    return problems


def validate(scenarios):
    problems = []
    seen_ids, seen_markers = {}, {}
    for sc in scenarios:
        sid = sc.get("id")
        label = str(sid)
        missing = [k for k in REQUIRED if k not in sc]
        unknown = [k for k in sc if not k.startswith("_") and k not in REQUIRED and k not in OPTIONAL]
        if missing:
            problems.append("%s: missing fields %s" % (label, missing))
            continue
        if unknown:
            problems.append("%s: unknown fields %s" % (label, unknown))
        if not (isinstance(sid, str) and ID_PATTERN.fullmatch(sid)):
            problems.append("%s: id must be letters, digits and underscores" % label)
        elif os.path.basename(sc["_dir"]) != sid:
            problems.append("%s: id does not match its directory name %s" % (label, os.path.basename(sc["_dir"])))
        if sid in seen_ids:
            problems.append("%s: duplicate id" % label)
        seen_ids[sid] = True
        for k in ("title", "threat_model", "notes"):
            if not (isinstance(sc[k], str) and sc[k].strip()):
                problems.append("%s: %s must be a non-empty string" % (label, k))
        if sc["known_gap"] is not None and not isinstance(sc["known_gap"], str):
            problems.append("%s: known_gap must be a string or null" % label)
        if sc["kind"] not in KINDS:
            problems.append("%s: kind must be attack or benign" % label)
        if sc["phase"] not in PHASES:
            problems.append("%s: phase must be after_loader or before_loader" % label)
        marker = sc["marker"]
        if not (isinstance(marker, str) and MARKER_PATTERN.fullmatch(marker)):
            problems.append("%s: marker must look like EVT_EVAL_NAME" % label)
        elif marker in seen_markers:
            problems.append("%s: marker %s is also used by %s" % (label, marker, seen_markers[marker]))
        else:
            seen_markers[marker] = label
        if type(sc["timeout_seconds"]) is not int or sc["timeout_seconds"] < 1:
            problems.append("%s: timeout_seconds must be a positive integer" % label)
        if sc["kind"] == "attack":
            if sc["technique"] not in attack_map.TECHNIQUES:
                problems.append("%s: technique %r is not in the attack map" % (label, sc["technique"]))
        elif sc["kind"] == "benign" and sc["technique"] is not None:
            problems.append("%s: a benign scenario has technique null" % label)
        problems += check_entries(label, "expected", sc["expected"], True)
        problems += check_entries(label, "acceptable", sc["acceptable"], False)
        if sc["kind"] == "benign" and sc["expected"]:
            problems.append("%s: a benign scenario has an empty expected list" % label)
        if sc["kind"] == "attack" and not sc["expected"]:
            problems.append("%s: an attack scenario needs at least one expected entry" % label)
        if "requires" in sc and not (isinstance(sc["requires"], list) and all(isinstance(r, str) for r in sc["requires"])):
            problems.append("%s: requires must be a list of command names" % label)
        if "tmp_staging" in sc and type(sc["tmp_staging"]) is not bool:
            problems.append("%s: tmp_staging must be true or false" % label)
        locations = sc.get("locations", [])
        if not (isinstance(locations, list) and all(x in LOCATIONS for x in locations)):
            problems.append("%s: locations must be a list of %s" % (label, ", ".join(LOCATIONS)))
            locations = []
        needs = sc.get("needs", [])
        if not (isinstance(needs, list) and all(x in NEEDS for x in needs)):
            problems.append("%s: needs must be a list of %s" % (label, ", ".join(NEEDS)))
            needs = []
        if "attribution" in sc:
            if sc["attribution"] not in ATTRIBUTIONS:
                problems.append("%s: attribution must be one of %s" % (label, ", ".join(ATTRIBUTIONS)))
            elif sc["attribution"] == "window" and sc["kind"] != "benign":
                problems.append("%s: attribution window is only allowed for a benign scenario" % label)
        if sc["kind"] == "attack" and sc["group"] not in GROUPS:
            problems.append("%s: group of an attack must be %s" % (label, " or ".join(GROUPS)))
        elif sc["kind"] == "benign" and sc["group"] is not None:
            problems.append("%s: a benign scenario has group null" % label)
        if sc["_scripts"]["action"] is None:
            problems.append("%s: action.sh is missing" % label)
        if sc["phase"] == "before_loader" and sc["_scripts"]["setup"] is None:
            problems.append("%s: a before_loader scenario needs setup.sh" % label)
        texts = {name: read_text(path) for name, path in sc["_scripts"].items() if path is not None}
        created = set().union(*[created_copies(x) for x in texts.values()]) if texts else set()
        for name, text in texts.items():
            for number, rule in lint_script(text, allow_tmp=bool(sc.get("tmp_staging")), locations=locations, created=created):
                problems.append("%s: unsafe script %s.sh line %d: %s" % (label, name, number, rule))
            if "EVT_EVAL_NONLOOPBACK_IPV4" in text and "non_loopback_ipv4" not in needs:
                problems.append("%s: %s.sh uses the non-loopback address without declaring the need" % (label, name))
    ids = [sc.get("marker") for sc in scenarios if isinstance(sc.get("marker"), str)]
    for a in ids:
        for b in ids:
            if a != b and a in b:
                problems.append("marker %s is contained in marker %s, which would mix their alerts" % (a, b))
    return problems


def label_hashes(scenarios):
    per = {sc["id"]: sc["_sha256"] for sc in scenarios}
    return {"scenarios": per, "set": set_hash(per)}
