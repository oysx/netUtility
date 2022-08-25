#!/usr/bin/bash
# run on client side(eth0: 10.10.20.1, want to connect to 10.25.53.1):
# $0 ipip0 172.77.7.2 10.10.10.1 10.25.53.0
# run on server side(eth0: 10.10.10.1, connected to subnet 10.25.53.0/24):
# $0 ipip0 172.77.7.1 10.10.20.1 10.25.53.0 1

set -ex
if (($#<2));then
        echo "Usage: $0 tunnel_nic_name local_tunnel_ip remote_real_ip dest_net [is_server]"
        exit 1
fi

tun_add(){
        local tunnel_nic=$1     #tunnel NIC name
        local tunnel_ip=$2      #ip address assigned to tunnel NIC
        local local_nic=$3      #real NIC name which mostly is physical NIC connected to outside
        local local_ip=$4       #ip address assigned to real NIC
        local remote_ip=$5      #remote ip address assigned on real NIC

        ip link add name $tunnel_nic type ipip local $local_ip remote  $remote_ip dev $local_nic
        ip link set $tunnel_nic up
        ip addr add $tunnel_ip/24 dev $tunnel_nic
}

net_setup(){
        if [ -z "$is_server" ];then
                # client side
                # add route to destination subnet via Tunnel interface
                ip route add $dest_net dev $tunnel_nic
        else
                if [ -n "$1" ];then
                        echo "Skip net_setup for server"
                        return
                fi

                # server side
                # do SNAT for outgoing packets to destination subnet
                iptables -t nat -A POSTROUTING -d $dest_net -o $local_nic -j MASQUERADE
                # the following commands are optional, if the policy of the FORWARD chain is ACCEPT
                iptables -A FORWARD -i $tunnel_nic -j ACCEPT
                iptables -A FORWARD -o $tunnel_nic -j ACCEPT
        fi
}

local_nic=$(ip route|grep default|cut -d\  -f5)
local_ip=$(ip addr show $local_nic |grep "inet\>"|awk '{print $2}' |cut -d/ -f1)
tunnel_nic=${1:-ipip0}
tunnel_ip=$2
remote_ip=$3
dest_net=$4     #destination subnet want to access via tunnel
is_server=$5


tun_add $tunnel_nic $tunnel_ip $local_nic $local_ip $remote_ip
net_setup