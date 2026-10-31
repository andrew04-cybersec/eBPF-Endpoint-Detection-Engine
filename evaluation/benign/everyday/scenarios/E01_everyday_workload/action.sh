DURATION=3600
cat > "$EVT_EVAL_WORK/driver.py" <<'PY'
"""
everyday workload driver: runs ordinary developer commands in random order for a fixed time and logs one line per command (standard library only)
Usage: driver.py DURATION_SECONDS [MARKER] (EVT_EVAL_WORK and EVT_EVAL_SEED come from the environment)
"""
import os
import random
import shutil
import subprocess
import sys
import time

#work directory is kept under this size; when it grows past the limit then the archives and scratch directories are emptied before the next task
MAX_WORK_BYTES = 150 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 300
THINK_SECONDS = (0.2, 3.0)
TASKS = (("build", 2), ("git", 3), ("python", 3), ("tar", 2), ("find", 3), ("grep", 3), ("ps", 1), ("ls", 4), ("sed", 3), ("files", 3))
SWAPS = (("alpha", "beta"), ("beta", "alpha"), ("gamma", "delta"), ("delta", "gamma"))
WORDS = ("alpha", "beta", "return", "int", "nomatchtoken")
SUMMARY_SCRIPT = [
    "import os",
    "import sys",
    "",
    "total = 0",
    "lines = 0",
    "for name in sorted(os.listdir(sys.argv[1])):",
    "    path = os.path.join(sys.argv[1], name)",
    "    if os.path.isfile(path):",
    "        with open(path) as f:",
    "            text = f.read()",
    "        total += len(text)",
    "        lines += text.count(chr(10))",
    "with open(sys.argv[2], 'w') as out:",
    "    out.write('%d %d' % (total, lines) + chr(10))",
]


class Workload:
    """the state of one run where every random choice comes from one random.Random(seed) so the same seed makes the same choices in the same order"""

    def __init__(self, work, seed, deadline):
        self.work = work
        self.rng = random.Random(seed)
        self.deadline = deadline
        self.count = 0
        self.unexpected = 0
        self.edits = 0
        self.spare = 0
        self.repo_ready = False
        self.proj = os.path.join(work, "proj")
        self.src = os.path.join(work, "proj", "src")
        self.repo = os.path.join(work, "repo")
        self.data = os.path.join(work, "data")
        self.archives = os.path.join(work, "archives")
        self.scripts = os.path.join(work, "scripts")
        self.scratch = os.path.join(work, "scratch")
        #temporary files where the home directory and every git configuration file stay inside the work directory
        self.env = dict(os.environ)
        self.env.update({"TMPDIR": self.scratch, "HOME": os.path.join(work, "h"), "XDG_CONFIG_HOME": os.path.join(work, "h", "xdg"),
                         "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"})

    def expired(self):
        return not time.monotonic_ns() < self.deadline

    def run(self, argv, cwd, expect=(0,)):
        """start one child from an argument list (never a shell) and log it; a return code not in expect is counted and a failure never stops the run (nothing is started after the deadline)"""
        if self.expired():
            return None
        self.count += 1
        index = self.count
        start = time.monotonic_ns()
        try:
            code = subprocess.run(argv, cwd=cwd, env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=COMMAND_TIMEOUT_SECONDS).returncode
        except subprocess.TimeoutExpired:
            code = "timeout"
        except OSError:
            code = "oserror"
        end = time.monotonic_ns()
        if code not in expect:
            self.unexpected += 1
        print("CMD %d %d %d %s %s" % (index, start, end, code, " ".join(argv)), flush=True)
        return code

    def edit(self, path):
        """append one line to ordinary text file in work directory"""
        self.edits += 1
        with open(path, "a") as f:
            f.write("edit %d value %d\n" % (self.edits, self.rng.randrange(1000)))

    def text_files(self):
        return [n for n in sorted(os.listdir(self.data)) if n.startswith("f") and n.endswith(".txt")]

    def prepare(self):
        with open(os.path.join(self.scripts, "summary.py"), "w") as f:
            f.write("\n".join(SUMMARY_SCRIPT) + "\n")

    def guard_size(self):
        total = 0
        for base, _, files in os.walk(self.work):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(base, name))
                except OSError:
                    pass
        if MAX_WORK_BYTES < total:
            for folder in (self.archives, self.scratch):
                shutil.rmtree(folder, ignore_errors=True)
                os.makedirs(folder, exist_ok=True)

    def git(self, *args):
        return ["git", "-c", "user.name=Everyday Workload", "-c", "user.email=workload@example.invalid"] + list(args)

    def task_build(self):
        self.run(["make", "-j4"], self.proj)
        self.run(["make", "clean"], self.proj)

    def task_git(self):
        notes = os.path.join(self.repo, "notes.txt")
        if not self.repo_ready:
            self.run(["git", "init", "-q"], self.repo)
            self.edit(notes)
            self.run(self.git("add", "notes.txt"), self.repo)
            self.run(self.git("commit", "-q", "-m", "first commit"), self.repo)
            self.repo_ready = True
            return
        choice = self.rng.choice(("status", "log", "diff", "commit"))
        if choice == "status":
            self.run(self.git("status", "--short"), self.repo)
        elif choice == "log":
            self.run(self.git("log", "--oneline", "-n", "5"), self.repo)
        elif choice == "diff":
            self.edit(notes)
            self.run(self.git("diff"), self.repo)
        else:
            self.edit(notes)
            self.run(self.git("add", "notes.txt"), self.repo)
            self.run(self.git("commit", "-q", "-m", "update %d" % self.edits), self.repo)

    def task_python(self):
        script = os.path.join(self.scripts, "summary.py")
        source = self.rng.choice((self.data, self.src))
        self.run(["python3", script, source, os.path.join(self.scratch, "summary.out")], self.work)

    def task_tar(self):
        self.spare += 1
        archive = os.path.join(self.archives, "a%d.tar" % self.spare)
        target = os.path.join(self.scratch, "x%d" % self.spare)
        os.makedirs(target, exist_ok=True)
        folder = self.rng.choice(("data", "proj"))
        self.run(["tar", "-cf", archive, "-C", self.work, folder], self.work)
        self.run(["tar", "-tf", archive], self.work)
        self.run(["tar", "-xf", archive, "-C", target], self.work)
        shutil.rmtree(target, ignore_errors=True)
        if os.path.exists(archive):
            os.remove(archive)

    def task_find(self):
        choices = (["find", self.proj, "-name", "*.c"], ["find", self.data, "-type", "f"],
                   ["find", self.repo, "-name", "*.txt", "-type", "f"], ["find", self.work, "-maxdepth", "2", "-type", "d"])
        self.run(self.rng.choice(choices), self.work)

    def task_grep(self):
        word = self.rng.choice(WORDS)
        place = self.rng.choice((self.proj, self.data))
        self.run(["grep", "-r", "-n", word, place], self.work, expect=(0, 1))

    def task_ps(self):
        self.run(["ps", "aux"], self.work)

    def task_ls(self):
        place = self.rng.choice((self.work, self.proj, self.src, self.data, self.repo))
        self.run(["ls", "-l", place], self.work)

    def task_sed(self):
        target = os.path.join(self.data, self.rng.choice(self.text_files()))
        mode = self.rng.choice(("range", "match", "inplace"))
        if mode == "range":
            self.run(["sed", "-n", "1,3p", target], self.work)
        elif mode == "match":
            self.run(["sed", "-n", "/%s/p" % self.rng.choice(WORDS), target], self.work)
        else:
            self.run(["sed", "-i", "s/%s/%s/" % self.rng.choice(SWAPS), target], self.work)

    def task_files(self):
        source = os.path.join(self.data, self.rng.choice(self.text_files()))
        self.spare += 1
        first = os.path.join(self.data, "copy%d.txt" % self.spare)
        second = os.path.join(self.data, "moved%d.txt" % self.spare)
        self.run(["cp", source, first], self.work)
        self.run(["mv", first, second], self.work)
        self.run(["rm", second], self.work)


def main(argv):
    seed_text = os.environ.get("EVT_EVAL_SEED", "")
    work = os.environ.get("EVT_EVAL_WORK", "")
    if not seed_text.isdigit():
        print("driver: EVT_EVAL_SEED is missing or not a number; start run_eval.py with --seed N", file=sys.stderr)
        return 2
    if not work or not os.path.isdir(work):
        print("driver: EVT_EVAL_WORK is not a directory", file=sys.stderr)
        return 2
    try:
        duration = float(argv[1])
    except (IndexError, ValueError):
        print("usage: driver.py DURATION_SECONDS [MARKER]", file=sys.stderr)
        return 2
    marker = argv[2] if 2 < len(argv) else ""
    start = time.monotonic_ns()
    deadline = start + int(duration * 1000000000)
    print("HEADER seed=%s duration_seconds=%s start_monotonic_ns=%d marker=%s" % (seed_text, argv[1], start, marker), flush=True)
    load = Workload(work, int(seed_text), deadline)
    load.prepare()
    names = [name for name, _ in TASKS]
    weights = [weight for _, weight in TASKS]
    while not load.expired():
        load.guard_size()
        getattr(load, "task_" + load.rng.choices(names, weights)[0])()
        pause = load.rng.uniform(THINK_SECONDS[0], THINK_SECONDS[1])
        remaining = (deadline - time.monotonic_ns()) / 1000000000
        time.sleep(max(0.0, min(pause, remaining)))
    print("SUMMARY commands=%d unexpected_nonzero=%d end_monotonic_ns=%d" % (load.count, load.unexpected, time.monotonic_ns()), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
PY
timeout $((DURATION + 120)) python3 "$EVT_EVAL_WORK/driver.py" "$DURATION" "$1"
:
