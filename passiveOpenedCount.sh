#!/bin/bash
# show passive opened connection count

field=7
timeinterval=0.05
TIMECOUNT=$(echo 1/$timeinterval|bc)
#show title
cat /proc/net/snmp|grep "^Tcp: [^[:digit:]]"|cut -d\  -f$field
#show value
oldval=`cat /proc/net/snmp|grep "^Tcp: [[:digit:]]"|cut -d\  -f$field`
maxval=0
timecount=0
while true;do
	sleep $timeinterval
	val=`cat /proc/net/snmp|grep "^Tcp: [[:digit:]]"|cut -d\  -f$field`
	deltaval=`expr $val - $oldval`
	if (( $deltaval > $maxval ));then
		maxval=$deltaval
	fi
	timecount=$(expr $timecount + 1)
	if (( $timecount >= $TIMECOUNT ));then
		timecount=0
		echo $(date +"%s") $maxval
	fi
	oldval=$val
done
