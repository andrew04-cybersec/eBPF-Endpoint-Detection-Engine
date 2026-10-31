set -eu
mkdir -p "$EVT_EVAL_WORK/src/pkg"
printf '#!/bin/sh\necho evt_eval tool\n' > "$EVT_EVAL_WORK/src/pkg/tool"
printf 'name=evt_eval\n' > "$EVT_EVAL_WORK/src/pkg/tool.conf"
cat > "$EVT_EVAL_WORK/src/pkg/install.sh" <<'EOF'
set -eu
mkdir -p "$EVT_EVAL_WORK/prefix/bin" "$EVT_EVAL_WORK/prefix/etc"
cp tool "$EVT_EVAL_WORK/prefix/bin/tool"
chmod +x "$EVT_EVAL_WORK/prefix/bin/tool"
cp tool.conf "$EVT_EVAL_WORK/prefix/etc/tool.conf"
printf 'installed %s\n' "$1" >> "$EVT_EVAL_WORK/prefix/etc/tool.conf"
"$EVT_EVAL_WORK/prefix/bin/tool" > /dev/null
EOF
tar -cf "$EVT_EVAL_WORK/pkg.tar" -C "$EVT_EVAL_WORK/src" pkg
rm -rf "$EVT_EVAL_WORK/src"
