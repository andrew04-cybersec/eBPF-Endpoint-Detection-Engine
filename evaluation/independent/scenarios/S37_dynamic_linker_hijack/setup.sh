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
