#!/bin/bash
#sudo iptables -t filter -A INPUT -p tcp -m tcp --dport $PORT --tcp-flags SYN SYN
#sudo iptables -t filter -A INPUT -p tcp -m tcp --dport $PORT --tcp-flags ACK ACK

doLog(){
	NET=$1
	TAG=$2
	DATA=`cat /proc/net/$NET|grep "^$TAG: [[:digit:]]"|sed 's/ /\t/g'`
#	k=0
#	for i in $DATA;do
#		if [ "$k" = "0" ];then
#			ODD[$k]=$i
#			k=$((k+1))
#			continue
#		fi
#		if [ "${ODD[$k]}" = "" ];then
#			ODD[$k]=0
#		fi
#		DD[$k]=$(($i-${ODD[$k]}))
#		ODD[$k]=$i
#		k=$((k+1))
#	done
	echo "$DATA" >> $ROOT/${TAG}.log
#	echo "${DD[*]}" >> $ROOT/${TAG}-rate.log
}

ROOT=~
cat /proc/net/snmp|grep "^Ip: [^[:digit:]]"|sed 's/ /\t/g' >> $ROOT/Ip.log
cat /proc/net/snmp|grep "^Tcp: [^[:digit:]]"|sed 's/ /\t/g' >> $ROOT/Tcp.log
cat /proc/net/netstat|grep "^TcpExt: [^[:digit:]]"|sed 's/ /\t/g' >> $ROOT/TcpExt.log
cat /proc/net/netstat|grep "^IpExt: [^[:digit:]]"|sed 's/ /\t/g' >> $ROOT/IpExt.log

ss -4tln|grep "^State" >> $ROOT/ss.log
getSockBuff(){
	ss -4tln|grep ":${1}[^[:digit:]]" >> $ROOT/ss.log
}

sudo iptables -t filter -v -L  INPUT|grep "pkts" >> $ROOT/iptables-ACK.log
sudo iptables -t filter -v -L  INPUT|grep "pkts" >> $ROOT/iptables-SYN.log
getIptables(){
	sudo iptables -t filter -v -L  INPUT|grep $1 >> $ROOT/iptables-$1.log
}

while [[ 1 ]];do
	sleep 1
	doLog "snmp" "Ip"
	doLog "snmp" "Tcp"
	doLog "netstat" "IpExt"
	doLog "netstat" "TcpExt"
	getSockBuff 80
	getIptables "ACK" 80
	getIptables "SYN" 80
done

