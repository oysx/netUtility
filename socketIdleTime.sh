#!/usr/bin/env bash

if (( $# < 1 )); then
	echo "Usage: $0 \"<ss-filter>\""
	exit 1
fi

#example filter: "dst :23"
filter="$1"
keyword=lastsnd

candidates=$(for i in $(ss -tnapi $filter);do echo $i;done|grep $keyword|cut -d: -f2)
for i in $candidates; do
	echo -n $keyword :
	date -d "@$(($(date +%s) - $i/1000))"
done

