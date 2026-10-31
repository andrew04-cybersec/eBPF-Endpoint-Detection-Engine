#!/bin/bash
#usage: bash check_sums.sh PATH_TO_SHA256SUMS ... read-only where it changes into the folder of the sums file so the paths inside are relative to it then prints OK or prints every failing file and exits 1
set -u
sums=${1:-}
if [ -z "$sums" ] || [ ! -f "$sums" ]; then
	echo "usage: bash check_sums.sh PATH_TO_SHA256SUMS" >&2
	exit 2
fi
cd "$(dirname "$sums")" || exit 2
if out=$(sha256sum -c "$(basename "$sums")" 2>&1); then
	echo OK
	exit 0
fi
printf '%s\n' "$out" | grep -v ': OK$'
exit 1
