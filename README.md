# eBPF Endpoint Detection Engine

A research prototype that watches process, file, network and privilege activity on Linux through eBPF tracepoints and raises alerts with ten behavioral detectors, each mapped to a MITRE ATT&CK technique. A C loader (libbpf, CO-RE) feeds a Python normalizer and runner that build a process graph and apply the detectors. It observes and alerts only. It is not production software.

## Research article

The design, evaluation and failures are written up in an 11-page paper:

- [PDF](article/ebpf-edr-flagship-short.pdf)
- [Markdown source](article/ebpf-edr-flagship-short.md)
- [Build instructions](article/README.md)

## Evaluation evidence

Scores, reports, summaries and checksums for the paper's numbers are in [evaluation/evidence](evaluation/evidence/README.md), which also lists which files support which claim. The raw event logs of the runs were not published, so the results can be checked for consistency but not regenerated from that folder.

## What was measured

All results come from one WSL2 machine (kernel 6.6.87.2-microsoft-standard-WSL2) with predictions frozen in Git before each run.

- 28 attack scenarios I wrote: 18 ordinary detected, 0 of 10 deliberate evasions detected.
- 8 further scenarios drafted from threat models: 2 of 8 detected under the frozen scoring rules.
- 8 benign near-miss scenarios: 5 false alerts.
- Three one-hour developer workloads: 466 false alerts (about 155.33 per hour), almost all from the `rapid_spawn` rule firing on parallel builds.
- Stress test: about 4,000 process executions per second with no ring-buffer loss counted by the loader, which is not a claim of complete event coverage.
- No overhead baseline was measured.

## Limitations

One machine and one kernel; detectors trust process names; many syscalls (for example `rename`) and `io_uring` are not hooked; scenario sets are small and written by the author; thresholds were not tuned.

## Build and run

These steps come from `telemetry/Makefile`, `run_unit_tests.sh` and the live test scripts in this repository. I developed and measured everything on WSL2 (Ubuntu 24.04, kernel 6.6.87.2-microsoft-standard-WSL2); other setups are untested.

**Prerequisites**

- A Linux kernel that exposes BTF at `/sys/kernel/btf/vmlinux` (the Makefile reads it to generate `vmlinux.h`).
- `clang`, `llvm-strip`, `gcc` and `make`.
- A working `bpftool`. On WSL the Makefile prefers the one under `/usr/lib/linux-tools/*/bpftool` because the `/usr/sbin/bpftool` wrapper does not work on that kernel.
- Development libraries for `libbpf`, `libelf` and `zlib` (the loader links `-lbpf -lelf -lz`).
- Python 3. The Python code imports only the standard library.
- `sudo`, because loading the eBPF programs needs root.

**Build the telemetry loader**

```bash
cd telemetry
make            # writes build/exec_exit_loader
```

**Run the unit tests** (no root needed)

```bash
bash run_unit_tests.sh
```

**Run the pipeline** (stages are loader, normalizer, runner, as in `detections/tests/live_test.sh`)

```bash
sudo telemetry/build/exec_exit_loader | python3 normalizer/normalize.py | python3 detections/runner.py
```

Alerts are written as JSON lines to standard output and in readable form to standard error; `runner.py -o FILE` writes the JSON lines to a file instead. `exec_exit_loader -h` lists its options.

**Run the evaluation**

```bash
sudo python3 evaluation/run_eval.py --dry-run   # validate scenarios and print the plan without starting anything
sudo python3 evaluation/run_eval.py             # real run; start from an otherwise idle machine
```

The driver records every process on the machine while it runs, so do not use the machine for anything else. The folder `evaluation/independent` holds the eight scenarios the paper calls the threat-model set. `docs/ARCHITECTURE.md` and `docs/EVENT_SCHEMA.md` hold the design notes and the event schema; some of their wording predates the implementation.

## License

No license has been chosen yet.
