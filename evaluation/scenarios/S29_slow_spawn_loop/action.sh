COUNT=30
SPACING=0.8
i=0
while [ "$i" -lt "$COUNT" ]; do
	/bin/true "$1"
	sleep "$SPACING"
	i=$((i + 1))
done
:
