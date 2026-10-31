set -eu
mkdir -p "$EVT_EVAL_WORK"
printf 'all:' > "$EVT_EVAL_WORK/Makefile"
i=1
while [ "$i" -le 400 ]; do
	printf ' t%d' "$i" >> "$EVT_EVAL_WORK/Makefile"
	i=$((i + 1))
done
printf '\n' >> "$EVT_EVAL_WORK/Makefile"
i=1
while [ "$i" -le 400 ]; do
	printf 't%d:\n\t@true\n' "$i" >> "$EVT_EVAL_WORK/Makefile"
	i=$((i + 1))
done
