set -eu
case "${EVT_EVAL_SEED:-}" in
	''|*[!0-9]*)
		echo "E01 needs a numeric EVT_EVAL_SEED; start run_eval.py with --seed N"
		exit 1
		;;
esac
missing=""
for tool in make gcc git python3 tar find grep ps sed timeout; do
	command -v "$tool" > /dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
	echo "E01 needs these commands and they are missing:$missing"
	exit 1
fi
mkdir -p "$EVT_EVAL_WORK/proj/src" "$EVT_EVAL_WORK/scratch" "$EVT_EVAL_WORK/h" "$EVT_EVAL_WORK/repo" "$EVT_EVAL_WORK/data" "$EVT_EVAL_WORK/archives" "$EVT_EVAL_WORK/scripts"
i=1
while [ "$i" -le 10 ]; do
	printf 'alpha beta gamma delta line %d\n' "$i" > "$EVT_EVAL_WORK/data/f$i.txt"
	printf 'beta gamma delta alpha again %d\n' "$i" >> "$EVT_EVAL_WORK/data/f$i.txt"
	printf 'gamma delta alpha beta last %d\n' "$i" >> "$EVT_EVAL_WORK/data/f$i.txt"
	i=$((i + 1))
done
printf '#include "all.h"\nint main(void)\n{\n\tint t = 0;\n' > "$EVT_EVAL_WORK/proj/src/main.c"
printf '' > "$EVT_EVAL_WORK/proj/src/all.h"
i=1
while [ "$i" -le 30 ]; do
	printf 'int f%d(int x)\n{\n\treturn x + %d;\n}\n' "$i" "$i" > "$EVT_EVAL_WORK/proj/src/mod$i.c"
	printf 'int f%d(int x);\n' "$i" >> "$EVT_EVAL_WORK/proj/src/all.h"
	printf '\tt += f%d(%d);\n' "$i" "$i" >> "$EVT_EVAL_WORK/proj/src/main.c"
	i=$((i + 1))
done
printf '\treturn t == 0;\n}\n' >> "$EVT_EVAL_WORK/proj/src/main.c"
cat > "$EVT_EVAL_WORK/proj/Makefile" <<'MK'
CC = gcc
CFLAGS = -O0
SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)

app: $(OBJS)
	$(CC) -o app $(OBJS)

clean:
	rm -f $(OBJS) app

.PHONY: clean
MK
