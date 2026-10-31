COUNT=60
i=0
while [ "$i" -lt "$COUNT" ]; do
	/bin/true "$1"
	i=$((i + 1))
done
:
