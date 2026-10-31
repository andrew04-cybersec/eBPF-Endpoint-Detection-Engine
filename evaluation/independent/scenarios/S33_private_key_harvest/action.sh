set -eu
find "$EVT_EVAL_HOME" -type f -name 'id_rsa' -print
cp "$EVT_EVAL_HOME/.ssh/id_rsa" "$EVT_EVAL_WORK/collected_private_key"
printf '%s\n' "$1" > "$EVT_EVAL_WORK/collection_marker"
