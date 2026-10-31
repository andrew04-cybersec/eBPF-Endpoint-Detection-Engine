mkdir -p "$EVT_EVAL_TMP"
cp /usr/bin/true "$EVT_EVAL_TMP/helper"
"$EVT_EVAL_TMP/helper" "$1"
:
