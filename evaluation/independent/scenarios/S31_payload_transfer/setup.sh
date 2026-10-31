set -eu
mkdir -p "$EVT_EVAL_WORK"

cat > "$EVT_EVAL_WORK/remote_payload" <<'PAYLOAD'
#!/bin/bash
printf '%s\n' "$1" > "$2"
PAYLOAD
