#obj-m += xt_u32.o
#obj-m += ipt_TOS.o
#ipt_TOS-objs = xt_VIVI.o
obj-m += nf_conntrack_httprtt.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	mkdir -p /lib/modules/$(shell uname -r)/kernel/net/ipv4/netfilter
	cp nf_conntrack_httprtt.ko /lib/modules/$(shell uname -r)/kernel/net/ipv4/netfilter/
	depmod -a

