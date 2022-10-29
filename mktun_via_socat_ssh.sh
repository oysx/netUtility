#!/bin/bash
# %LOCAL%:
#   HOST.APP.send(UDP.6081) => HOST.policy_routing(match: UDP+dport=6081, action: to-container's IP) => CONTAINER.iptables.DNAT(to local-IP) => CONTAINER.socat(UDP.6081 <-> TCP.7770) => CONTAINER.ssh(tunnel: local.7770 -> remote.7771) => %REMOTE%
# %REMOTE%:
#   CONTAINER.export_port(7771) => CONTAINER.socat(TCP.7771 <-> HOST.UDP.6081) => HOST.APP.recv(UDP:6081)
# %DOCKER-IMAGE%: must have "socat" program and "iptables" and "sshpass" and "ssh"

if (( $# < 4 )); then
        echo "Usage: $0 main <peer_user> <peer_password> <peer_ip> [local_ip]"
        exit 1
fi

OUT_TCP_PORT=7770
IN_TCP_PORT=7771
OUT_UDP_PORT=6081
IN_UDP_PORT=6081
LOG_DIR=${HOME}
ME=$(readlink -f $BASH_SOURCE)

get_nic(){
        echo $(ip route|grep default|cut -d\  -f5) 
}

get_ip(){
        echo $(ip addr show $(get_nic) |grep "inet "|awk '{print $2}'|cut -d/ -f1)
}

PEER_USER=${2}
PEER_PASSWD=${3}
PEER_IP=${4}
LOCAL_IP=${5}

in_docker(){
        local INNER_IP=$(get_ip)
        local OUTER_IP=$LOCAL_IP

        sshpass -p "$PEER_PASSWD" ssh -E $LOG_DIR/ssh-err.log -o "StrictHostKeyChecking=no" -o "ServerAliveInterval=120" -N -L $OUT_TCP_PORT:$PEER_IP:$IN_TCP_PORT $PEER_USER@$PEER_IP &
        echo "ssh result: $?"
        sleep 2

        socat -lf $LOG_DIR/socat-in.log -d -d tcp4-l:$IN_TCP_PORT,reuseaddr,fork,keepalive UDP4:$OUTER_IP:$IN_UDP_PORT &

        socat -lf $LOG_DIR/socat-out.log -d -d UDP4-RECVFROM:$OUT_UDP_PORT,fork tcp4:localhost:$OUT_TCP_PORT,keepalive &

        #do DNAT
        iptables -t nat -A PREROUTING -p udp --dport $OUT_UDP_PORT -j DNAT --to-destination $INNER_IP:$OUT_UDP_PORT

        #wait forever
        while true; do
                sleep 3600
        done
}


# app send
#nc -u 127.0.0.1 $OUT_UDP_PORT
# app recv
#nc -u -l $IN_UDP_PORT

get_docker_ip(){
        echo $(docker inspect --format '{{ .NetworkSettings.IPAddress }}' $1)
}

get_docker_mac(){
        echo $(docker inspect --format '{{ .NetworkSettings.MacAddress }}' $1)
}

get_docker_peer_nic(){
        local in_nic=$(docker exec $1 ip route|grep default|cut -d\  -f5)
        local out_ifindex=$(docker exec $1 ip -j link show $in_nic |jq '.[].link_index')
        echo $(ip link | grep "^$out_ifindex:" | cut -d\  -f2 | cut -d\@ -f1)
}

# The following two methods are exclusive and be choiced only one
policy_routing(){
        #in host, do policy routing
        local docker_ip=$(get_docker_ip $1)
        echo "container ip: $docker_ip"

        ip rule add ipproto udp dport $OUT_UDP_PORT to $PEER_IP lookup 7
        ip rule list
        ip route add default via $docker_ip table 7
	ip route list table 7

	#remove setting:
	echo "Use following commands to undo:"
	echo "  ip rule del to $PEER_IP ipproto udp dport $OUT_UDP_PORT lookup 7"
	echo "  ip route del default table 7"
}

tc_redirect(){
        #in host, do tc change dmac and redirect packet
        local docker_mac=$(get_docker_mac $1)
        echo "container mac: $docker_mac"
        
        local hostNIC=$(get_nic)
        local containerNIC=$(get_docker_peer_nic $1)
        tc qdisc add dev $hostNIC root handle 1: htb
        tc filter add dev $hostNIC parent 1: protocol ip u32 \
                match ip dst $PEER_IP \
                match u16 $OUT_UDP_PORT 0xffff at 22 \
                action skbmod set dmac $docker_mac pipe \
                action mirred egress redirect dev $containerNIC

        #disable tx checksum offloading on both NICs to workaround the checksum error caused by TC mechanism:
	echo "Use following command to workaround checksum error issue:"
	echo "  ethtool --offload eth0 tx off"
	
	#remove setting:
	echo "Use following commands to undo:"
	echo "  tc qdisc del dev $hostNIC root"
}

main(){
        # in host, run docker contains above setting
        local local_ip=$(get_ip)
        local container=$(docker run -dt --rm --privileged -p$IN_TCP_PORT:$IN_TCP_PORT -v$ME:/root/mktun_via_socat_ssh.sh \
                vilocal.vpn \
                /root/mktun_via_socat_ssh.sh \
                in_docker $PEER_USER $PEER_PASSWD $PEER_IP $local_ip)

        echo "container is $container"
        
        # Use policy_routing or tc_redirect, not both
        policy_routing $container
        #tc_redirect $container
}

$1
