# Linux Endpoint Detection Evaluation: Scenarios S30–S37

Draft scenarios from the preceding response. These have not been validated against the harness.

### S30_service_shell
Technique: T1059.004, Unix Shell. A compromised service worker invokes a shell to execute attacker-supplied commands. A competent endpoint detector should flag the behavior.

Assumption: A background worker represents the compromised service without creating a real network listener.

```json
{
  "id": "S30_service_shell",
  "title": "Compromised Service Worker Shell Execution",
  "technique": "T1059.004",
  "threat_model": "A compromised long-running service worker executes attacker commands through a Unix shell.",
  "phase": "after_loader",
  "marker": "EVT_EVAL_S30_SERVICE_SHELL",
  "timeout_seconds": 15,
  "notes": "Simulates shell execution from a long-running worker using harmless commands and a marker-bearing output artifact.",
  "requires": ["bash", "sleep", "mkdir", "rm", "cat"]
}
```

```bash setup.sh
set -eu
mkdir -p "$EVT_EVAL_WORK"
```

```bash action.sh
set -eu
marker="$1"

bash -c '
  sleep 1
  bash -c '\''printf "%s\n" "$1" > "$2"'\'' worker "$1" "$2"
' service_worker "$marker" "$EVT_EVAL_WORK/command_result"

cat "$EVT_EVAL_WORK/command_result"
```

```bash teardown.sh
rm -rf "$EVT_EVAL_WORK"
```

### S31_payload_transfer
Technique: T1105, Ingress Tool Transfer. An attacker transfers an executable payload onto the compromised host and runs it. A competent endpoint detector should flag the behavior.

Substitution note: A prepared local source file models payload bytes received from a remote host. Copying it into a separate destination models the completed transfer, without actual network communication.

```json
{
  "id": "S31_payload_transfer",
  "title": "Transferred Payload Execution",
  "technique": "T1105",
  "threat_model": "An attacker brings a payload onto the compromised host, makes it executable, and launches it.",
  "phase": "after_loader",
  "marker": "EVT_EVAL_S31_PAYLOAD_TRANSFER",
  "timeout_seconds": 15,
  "notes": "Local source-to-destination copy substitutes for a completed remote payload transfer.",
  "requires": ["bash", "cp", "chmod", "mkdir", "rm"]
}
```

```bash setup.sh
set -eu
mkdir -p "$EVT_EVAL_WORK"

cat > "$EVT_EVAL_WORK/remote_payload" <<'PAYLOAD'
#!/bin/bash
printf '%s\n' "$1" > "$2"
PAYLOAD
```

```bash action.sh
set -eu
cp "$EVT_EVAL_WORK/remote_payload" "$EVT_EVAL_WORK/received_payload"
chmod 700 "$EVT_EVAL_WORK/received_payload"
"$EVT_EVAL_WORK/received_payload" "$1" "$EVT_EVAL_WORK/execution_result"
```

```bash teardown.sh
rm -rf "$EVT_EVAL_WORK"
```

### S32_password_material
Technique: T1003.008, OS Credential Dumping. An attacker accesses local account and password-hash material. A competent endpoint detector should flag credential harvesting.

Substitution note: Reading actual `/etc/passwd` and `/etc/shadow` would violate the sandbox's prohibition on accessing real credential material. Synthetic files inside the work directory substitute for those databases. This tests the workflow, not detection of the actual protected paths.

```json
{
  "id": "S32_password_material",
  "title": "Local Password Database Harvesting",
  "technique": "T1003.008",
  "threat_model": "An attacker with elevated access collects account records and password-hash material for offline analysis.",
  "phase": "after_loader",
  "marker": "EVT_EVAL_S32_PASSWORD_MATERIAL",
  "timeout_seconds": 15,
  "notes": "Uses synthetic passwd and shadow fixtures, without reading real operating-system credential databases.",
  "requires": ["bash", "cat", "cp", "mkdir", "rm", "grep"]
}
```

```bash setup.sh
set -eu
mkdir -p "$EVT_EVAL_WORK"
cat > "$EVT_EVAL_WORK/passwd" <<'PASSWD'
demo_user:x:1001:1001:Demo User:/home/demo_user:/bin/bash
PASSWD
cat > "$EVT_EVAL_WORK/shadow" <<'SHADOW'
demo_user:$6$synthetic$not_a_real_password_hash:20000:0:99999:7:::
SHADOW
```

```bash action.sh
set -eu
cp "$EVT_EVAL_WORK/passwd" "$EVT_EVAL_WORK/collected_passwd"
cp "$EVT_EVAL_WORK/shadow" "$EVT_EVAL_WORK/collected_shadow"
grep '^demo_user:' "$EVT_EVAL_WORK/collected_passwd"
grep '^demo_user:' "$EVT_EVAL_WORK/collected_shadow"
printf '%s\n' "$1" > "$EVT_EVAL_WORK/collection_marker"
```

```bash teardown.sh
rm -rf "$EVT_EVAL_WORK"
```

### S33_private_key_harvest
Technique: T1552.004, Unsecured Credentials: Private Keys. An attacker searches a user's home directory and copies accessible private key material. A competent endpoint detector should flag the behavior.

Substitution note: The private key is a deliberately invalid fixture, not a functioning authentication credential.

```json
{
  "id": "S33_private_key_harvest",
  "title": "Private Key Material Harvesting",
  "technique": "T1552.004",
  "threat_model": "An attacker searches a user's home directory for private keys and collects accessible key files.",
  "phase": "after_loader",
  "marker": "EVT_EVAL_S33_PRIVATE_KEY_HARVEST",
  "timeout_seconds": 15,
  "notes": "Harvests an invalid synthetic SSH private key from an isolated fake home directory.",
  "locations": ["home"],
  "requires": ["bash", "find", "cp", "mkdir", "rm"]
}
```

```bash setup.sh
set -eu
mkdir -p "$EVT_EVAL_HOME/.ssh"
mkdir -p "$EVT_EVAL_WORK"
cat > "$EVT_EVAL_HOME/.ssh/id_rsa" <<'KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
SYNTHETIC_INVALID_KEY_MATERIAL
-----END OPENSSH PRIVATE KEY-----
KEY
```

```bash action.sh
set -eu
find "$EVT_EVAL_HOME" -type f -name 'id_rsa' -print
cp "$EVT_EVAL_HOME/.ssh/id_rsa" "$EVT_EVAL_WORK/collected_private_key"
printf '%s\n' "$1" > "$EVT_EVAL_WORK/collection_marker"
```

```bash teardown.sh
rm -rf "$EVT_EVAL_HOME"
rm -rf "$EVT_EVAL_WORK"
```

### S34_raw_command_channel
Technique: T1095, Non-Application Layer Protocol. An attacker establishes a host command channel without relying on a standard application protocol. A competent endpoint detector should flag the behavior.

Substitution note: A local Unix-domain socket models bidirectional command-channel message exchange without real network access. It does not reproduce raw IP, ICMP, or other non-application-layer network traffic, so this is a limited approximation.

```json
{
  "id": "S34_raw_command_channel",
  "title": "Local Command Channel Simulation",
  "technique": "T1095",
  "threat_model": "An attacker establishes a bidirectional command channel using messages outside a standard application protocol.",
  "phase": "after_loader",
  "marker": "EVT_EVAL_S34_COMMAND_CHANNEL",
  "timeout_seconds": 15,
  "notes": "Uses a local Unix-domain socket for inert command-and-response exchange; no network traffic or command execution.",
  "requires": ["python3", "mkdir", "rm"]
}
```

```bash setup.sh
set -eu
mkdir -p "$EVT_EVAL_WORK"
```

```bash action.sh
set -eu
python3 - "$EVT_EVAL_WORK/channel.sock" "$1" <<'PY'
import socket
import sys
import threading

path, marker = sys.argv[1:]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.settimeout(5)
server.bind(path)
server.listen(1)

def receive():
    connection, _ = server.accept()
    with connection:
        data = connection.recv(1024)
        if data == marker.encode():
            connection.sendall(b"ACK")

thread = threading.Thread(target=receive)
thread.start()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    client.connect(path)
    client.sendall(marker.encode())
    assert client.recv(1024) == b"ACK"
thread.join(timeout=5)
server.close()
PY
```

```bash teardown.sh
rm -rf "$EVT_EVAL_WORK"
```

### S35_cron_persistence
Technique: T1053.003, Scheduled Task/Job: Cron. An attacker installs a scheduled job to reexecute a command periodically. A competent endpoint detector should flag the persistence behavior.

Assumption: The harness permits a scenario-specific cron definition, but does not guarantee that the cron daemon is active. The test therefore validates job installation rather than waiting for execution.

```json
{
  "id": "S35_cron_persistence",
  "title": "Scheduled Cron Persistence",
  "technique": "T1053.003",
  "threat_model": "An attacker establishes persistence by creating a recurring cron job.",
  "phase": "after_loader",
  "marker": "EVT_EVAL_S35_CRON_PERSISTENCE",
  "timeout_seconds": 15,
  "notes": "Creates an isolated cron definition invoking a harmless marker-writing script; does not depend on a cron tick.",
  "locations": ["cron"],
  "requires": ["bash", "mkdir", "chmod", "rm", "cat"]
}
```

```bash setup.sh
set -eu
mkdir -p "$EVT_EVAL_WORK"
cat > "$EVT_EVAL_WORK/periodic_task.sh" <<'TASK'
#!/bin/bash
printf '%s\n' "$EVT_EVAL_MARKER" > "$EVT_EVAL_WORK/cron_result"
TASK
chmod 700 "$EVT_EVAL_WORK/periodic_task.sh"
```

```bash action.sh
set -eu
printf '* * * * * root /bin/bash %s/periodic_task.sh\n' "$EVT_EVAL_WORK" > "$EVT_EVAL_CRON_FILE"
printf '%s\n' "$1" > "$EVT_EVAL_WORK/installation_marker"
```

```bash teardown.sh
rm -f "$EVT_EVAL_CRON_FILE"
rm -rf "$EVT_EVAL_WORK"
```

### S36_shell_startup
Technique: T1546.004, Event Triggered Execution: Unix Shell Configuration Modification. An attacker modifies a user's shell initialization state to execute a command when an interactive shell starts. A competent endpoint detector should flag the persistence behavior.

```json
{
  "id": "S36_shell_startup",
  "title": "Shell Initialization Persistence",
  "technique": "T1546.004",
  "threat_model": "An attacker plants commands in a user's shell startup configuration to run during subsequent interactive sessions.",
  "phase": "after_loader",
  "marker": "EVT_EVAL_S36_SHELL_STARTUP",
  "timeout_seconds": 15,
  "notes": "Uses an isolated fake home and an explicit Bash startup-file invocation to verify execution.",
  "locations": ["home"],
  "requires": ["bash", "mkdir", "rm", "cat"]
}
```

```bash setup.sh
set -eu
mkdir -p "$EVT_EVAL_HOME"
mkdir -p "$EVT_EVAL_WORK"
```

```bash action.sh
set -eu
cat > "$EVT_EVAL_HOME/.bashrc" <<'RC'
printf '%s\n' "$EVT_EVAL_MARKER" > "$EVT_EVAL_WORK/shell_startup_result"
RC
bash --noprofile --rcfile "$EVT_EVAL_HOME/.bashrc" -ic 'exit 0'
```

```bash teardown.sh
rm -rf "$EVT_EVAL_HOME"
rm -rf "$EVT_EVAL_WORK"
```

### S37_dynamic_linker_hijack
Technique: T1574.006, Hijack Execution Flow: Dynamic Linker Hijacking. An attacker causes a program to load attacker-controlled shared-library code during startup. A competent endpoint detector should flag the behavior.

Substitution note: The simulation uses `LD_PRELOAD` scoped to a single test process instead of modifying global dynamic-linker configuration. It demonstrates the shared-library loading mechanism without changing system files.

```json
{
  "id": "S37_dynamic_linker_hijack",
  "title": "Process-Scoped Dynamic Linker Hijacking",
  "technique": "T1574.006",
  "threat_model": "An attacker influences a program's dynamic library loading so attacker-controlled code executes during process initialization.",
  "phase": "after_loader",
  "marker": "EVT_EVAL_S37_LINKER_HIJACK",
  "timeout_seconds": 20,
  "notes": "Compiles a harmless shared-library constructor and loads it into one test process through a process-scoped environment variable.",
  "requires": ["bash", "gcc", "mkdir", "rm", "cat"]
}
```

```bash setup.sh
set -eu
mkdir -p "$EVT_EVAL_WORK"
cat > "$EVT_EVAL_WORK/library.c" <<'C'
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
static void initialization(void) {
    const char *marker = getenv("EVT_EVAL_MARKER");
    const char *work = getenv("EVT_EVAL_WORK");
    if (!marker || !work) return;
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/library_result", work)
        >= (int)sizeof(path)) return;
    FILE *file = fopen(path, "w");
    if (file) {
        fprintf(file, "%s\n", marker);
        fclose(file);
    }
}
C
gcc -shared -fPIC -o "$EVT_EVAL_WORK/library.so" "$EVT_EVAL_WORK/library.c"
```

```bash action.sh
set -eu
LD_PRELOAD="$EVT_EVAL_WORK/library.so" /bin/true
cat "$EVT_EVAL_WORK/library_result"
```

```bash teardown.sh
rm -rf "$EVT_EVAL_WORK"
```
