#!/bin/bash
# show current passive connection and active connection

passiveField=7
activeField=6
#show title
title=`cat /proc/net/snmp|grep "^Tcp: [^[:digit:]]"|cut -d\  -f$passiveField`" "`cat /proc/net/snmp|grep "^Tcp: [^[:digit:]]"|cut -d\  -f$activeField`
echo $title 
#show value
oldPassiveVal=`cat /proc/net/snmp|grep "^Tcp: [[:digit:]]"|cut -d\  -f$passiveField`
oldActiveVal=`cat /proc/net/snmp|grep "^Tcp: [[:digit:]]"|cut -d\  -f$activeField`

while true;do
	sleep 1
	passiveVal=`cat /proc/net/snmp|grep "^Tcp: [[:digit:]]"|cut -d\  -f$passiveField`
	activeVal=`cat /proc/net/snmp|grep "^Tcp: [[:digit:]]"|cut -d\  -f$activeField`
	toPrint=`expr $passiveVal - $oldPassiveVal`" "`expr $activeVal - $oldActiveVal`
	printf '%7d %7d\n' `expr $passiveVal - $oldPassiveVal` `expr $activeVal - $oldActiveVal`
	oldPassiveVal=$passiveVal
	oldActiveVal=$activeVal
done
