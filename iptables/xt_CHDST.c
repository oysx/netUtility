// Derived from xt_DSCP.c
/*
- This works with libxt_CHDST.c for iptables
- Usage:
	#in this host#: iptables -t mangle -I OUTPUT -p udp --dport <original port> -j CHDST --dport <chdst-port>
- Since it has changed the udp port before sent out, you must add corresponding DNAT rule in peer host to convert to original udp port and vice versa.
	#in peer host#: iptables -t nat -I PREROUTING -p udp --dport <chdst-port> -j DNAT --to-destination <peer host ip>:<original port>
- INSTALL:
	make
	insmod xt_CHDST.ko
*/
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/printk.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_tcpudp.h>

MODULE_AUTHOR("vivi");
MODULE_DESCRIPTION("change udp sport/dport in mangle table");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_CHDST");

static unsigned int
_chdst_action(struct sk_buff *skb, __u16 port, __be16 *portptr, const char *dir)
{
	struct udphdr *udp = udp_hdr(skb);
	u_int16_t oldport = htons(udp->dest);
	__be16 newport;

	if (!!port && oldport != port) {
		if (skb_ensure_writable(skb, sizeof(struct iphdr)+sizeof(struct udphdr)))
			return NF_DROP;

		printk("VI-CHDST.action(%s): %d->%d\n", dir, oldport, port);
		newport = htons(port);
		if(!!udp->check){
			inet_proto_csum_replace2(&udp->check, skb, *portptr, newport, false);
			if (!udp->check)
				udp->check = CSUM_MANGLED_0;
		}
		*portptr = newport;
	}
	return XT_CONTINUE;
}

static unsigned int
chdst_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	unsigned int ret;
	struct udphdr *udp = udp_hdr(skb);
	const struct xt_udp *dinfo = par->targinfo;
	ret = _chdst_action(skb, dinfo->dpts[0], &udp->dest, "dport");
	if(ret == NF_DROP){
		return ret;
	}
	return _chdst_action(skb, dinfo->spts[0], &udp->source, "sport");
}

static int chdst_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_udp *info = par->targinfo;
	printk("VI-CHDST: dport=%d,sport=%d\n", info->dpts[0], info->spts[0]);

	if (!!info->invflags)
		return -EDOM;
	return 0;
}

static struct xt_target chdst_tg_reg[] __read_mostly = {
	{
		.name		= "CHDST",
		.family		= NFPROTO_IPV4,
		.checkentry	= chdst_tg_check,
		.target		= chdst_tg,
		.targetsize	= sizeof(struct xt_udp),
		.table		= "mangle",
		.hooks      = (1 << NF_INET_POST_ROUTING) | (1 << NF_INET_LOCAL_OUT),
		.me			= THIS_MODULE,
	},
};

static int __init chdst_tg_init(void)
{
	return xt_register_targets(chdst_tg_reg, ARRAY_SIZE(chdst_tg_reg));
}

static void __exit chdst_tg_exit(void)
{
	xt_unregister_targets(chdst_tg_reg, ARRAY_SIZE(chdst_tg_reg));
}

module_init(chdst_tg_init);
module_exit(chdst_tg_exit);
