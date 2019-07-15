#Attention: must use following command to disable variable packets offload functionality! Otherwise, the stap script "tcpCount.stp" can't get the correct result and it will calculate the "rcv" count larger than "snd" count!!

ethtool -K eth0 tso off
ethtool -K eth0 gso off
ethtool -K eth0 gro off
ethtool -K eth0 lro off
