/* FTP extension for connection tracking. */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2003,2004 USAGI/WIDE Project <http://www.linux-ipv6.org>
 * (C) 2006-2012 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <net/checksum.h>
#include <net/tcp.h>
#include <linux/atomic.h>

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rusty Russell <rusty@rustcorp.com.au>");
MODULE_DESCRIPTION("http-rtt connection tracking helper");
MODULE_ALIAS("ip_conntrack_httprtt");
MODULE_ALIAS_NFCT_HELPER("httprtt");

typedef typeof(jiffies_64) ts64;
typedef enum{
	cABOVE,
	cTOTAL,
	cMAX,

	cSIZEOF,
}viResultCounter_t;

struct nf_ct_httprtt_master {
	ts64 timestamp;
	ulong done;
	ulong close;
	ulong count;
};

#define SIM_STOLEN

#define CONF_LOG_RTT (1<<0)
#define CONF_LOG_CT (1<<1)
#define CONF_LOG_SK (1<<2)

static ushort conf_port=8000;
static ulong conf_threshold_ttfb=100;//ms
static ulong conf_threshold_rtd=1000;//ms
static ulong conf_dolog=(CONF_LOG_SK|CONF_LOG_RTT);
static ulong conf_simdrop=1;
module_param(conf_port, ushort, 0700);
module_param(conf_threshold_ttfb, ulong, 0700);
module_param(conf_threshold_rtd, ulong, 0700);
module_param(conf_dolog, ulong, 0700);
module_param(conf_simdrop, ulong, 0700);

static atomic_t result_counter[cSIZEOF*2]={ATOMIC_INIT(0),ATOMIC_INIT(0),ATOMIC_INIT(0),ATOMIC_INIT(0),ATOMIC_INIT(0),ATOMIC_INIT(0)};

static inline void maximum(int val, atomic_t *max) {
	int old, to=10, ret;
	old = atomic_read(max);
	if (val > old) {
		while(--to) {
			ret = atomic_cmpxchg(max, old, val);
			if (ret == old) return;
		}
		printk(KERN_ERR "busy for setting maximum!\n");
	}
}

static void statistic(ts64 rtt, char *name, ulong threshold, atomic_t *counter) {
	if (rtt >= threshold) {
		atomic_inc(&counter[cABOVE]);
	}
	atomic_inc(&counter[cTOTAL]);
	maximum((int)rtt, &counter[cMAX]);
	if (conf_dolog&CONF_LOG_RTT) {
		printk(KERN_ERR "%s:%d\n", name, (int)rtt);
	}
}

static int help(struct sk_buff *skb,
		unsigned int protoff,
		struct nf_conn *ct,
		enum ip_conntrack_info ctinfo)
{
#define ICSK(field, def) sk?(inet_csk(sk)->field):def
#define TP(field, def) sk?(tcp_sk(sk)->field):def
#define J2MS(v) jiffies_to_usecs(v)/1000
#define FORMAT "%d->%d, SYN=%d, ACK=%d, FIN=%d, RST=%d, PUSH=%d, seq=%u, ack_seq=%u, skb=0x%p, rto=%d, state=%d, ca=%d, reTS=%d, rtt=%d, bkoff=%d, prbout=%d, retrans=%d, pktfly=%d, cwnd=%d, pcount=%d, "
#define DATA sport, dport, th->syn, th->ack, th->fin, th->rst, th->psh, ntohl(th->seq), ntohl(th->ack_seq), (void*)skb, J2MS(ICSK(icsk_rto,0)), sk?sk->sk_state:255, ICSK(icsk_ca_state,255), J2MS(TP(retrans_stamp,0)), J2MS(TP(srtt,0)), ICSK(icsk_backoff,255), ICSK(icsk_probes_out,255), ICSK(icsk_retransmits,255), TP(packets_out, 0), TP(snd_cwnd, 255), tcp_skb_pcount(skb) 

#define IS_CLOSING (th->fin || th->rst || (sk?sk->sk_state!=TCP_ESTABLISHED:0))

	char *type=0;
	unsigned int dataoff, datalen;
	const struct tcphdr *th;
	struct tcphdr _tcph;
	struct sock	*sk = skb->sk;
	int ret=NF_ACCEPT;
	ushort dport,sport;
	ts64 delta;
	int dir = CTINFO2DIR(ctinfo);
	struct nf_ct_httprtt_master *ct_httprtt_info = nfct_help_data(ct);
	char *drop="";

	sport = ntohs(ct->tuplehash[dir].tuple.src.u.tcp.port);
	dport = ntohs(ct->tuplehash[dir].tuple.dst.u.tcp.port);

	if (conf_dolog&CONF_LOG_CT) {
		printk(KERN_ERR "%d->%d: ctinfo=%u\n", sport, dport, ctinfo);
	}
	
	/* Until there's been traffic both ways, don't look in packets. */
	if (ctinfo != IP_CT_ESTABLISHED &&
	    ctinfo != IP_CT_ESTABLISHED_REPLY) {
		pr_debug("httprt: Conntrackinfo = %u\n", ctinfo);
		return NF_ACCEPT;
	}

	th = skb_header_pointer(skb, protoff, sizeof(_tcph), &_tcph);
	if (th == NULL)
		return NF_ACCEPT;

	dataoff = protoff + th->doff * 4;

	type="HDR";
	if (dataoff >= skb->len) {
		ret = NF_ACCEPT;
		goto _myexit;
	}
	datalen = skb->len - dataoff;

    if (dport == conf_port) {
		type="REQ";
		//request
		if (!ct_httprtt_info->timestamp) {
			ct_httprtt_info->timestamp = get_jiffies_64();
		}
	}
	else if (sport == conf_port) {
		type="RSP";
		//response
		if (!ct_httprtt_info->done && ct_httprtt_info->timestamp) {
			delta = get_jiffies_64() - ct_httprtt_info->timestamp;
			delta = J2MS(delta);
			ct_httprtt_info->done = 1;
			statistic(delta, "TTFB", conf_threshold_ttfb, &result_counter[0]);
		}
	}
	
_myexit:
	//RTD calculate
	if (IS_CLOSING && !ct_httprtt_info->close && ct_httprtt_info->timestamp) {
		ct_httprtt_info->close = 1;
		delta = get_jiffies_64() - ct_httprtt_info->timestamp;
		delta = J2MS(delta);
		statistic(delta, "RTD", conf_threshold_rtd, &result_counter[cSIZEOF]);
	}
	
	if (conf_simdrop) {
		//simulate drop
		if(sport==conf_port && !th->syn && !th->fin && !th->rst && ct_httprtt_info->count<13){
			ct_httprtt_info->count++;
			if(th->psh || ct_httprtt_info->count%3){
				drop="(drop)";
#ifdef SIM_STOLEN
				//use STOLEN style to simulate packets drop
				ret = NF_STOLEN;
				kfree_skb(skb);
#else
				//use DROP style to simulate packets drop
				ret = NF_DROP;
#endif
			}
		}
	}
	
	if (conf_dolog&CONF_LOG_SK) {
		char *dataptr = 0;
		char data[5] = {0,0,0,0,0};
		if (dataoff < skb->len) {
			dataptr=skb_header_pointer(skb, dataoff, 4, data);
			if(dataptr!=&data[0]){
				memcpy(data, dataptr, 4);
			}
			//show a special mark if the first byte is zero
			if(!data[0]){
				data[0]='\\';data[1]='0';data[2]='.';data[3]='.';
			}
		}
		printk(KERN_ERR "%s:" FORMAT " data=[%s] %s\n", type, DATA, data, drop);
	}
	return ret;
}

static const struct nf_conntrack_expect_policy httprtt_exp_policy = {
    .max_expected	= 1,
};

static struct nf_conntrack_helper httprtt __read_mostly = {
	.me			= THIS_MODULE,
	.help			= help,
	.expect_policy		= &httprtt_exp_policy,
	.name			= "httprtt",
	.data_len		= sizeof(struct nf_ct_httprtt_master),
	.tuple.src.l3num	= AF_INET,
	.tuple.dst.protonum	= IPPROTO_TCP,
};

static void nf_conntrack_httprtt_fini(void)
{
	printk(KERN_ERR "nf_ct_httprtt: fini\n");
	remove_proc_entry("httprtt", init_net.proc_net);
	remove_proc_entry("httprtt_conf", init_net.proc_net);
	nf_conntrack_helper_unregister(&httprtt);
}

static void *m_start(struct seq_file *m, loff_t *pos)
__acquires(RCU)
{
    rcu_read_lock();
    if (!*pos)
        return SEQ_START_TOKEN;
    return NULL;
}

static void *m_next(struct seq_file *m, void *p, loff_t *pos)
{
    ++*pos;
	return NULL;
}

static void m_stop(struct seq_file *m, void *p)
__releases(RCU)
{
    rcu_read_unlock();
}

static int m_show(struct seq_file *m, void *p)
{
	seq_printf(m, "ttfb.lt=%d ttfb.count=%d ttfb.max=%d rtd.lt=%d rtd.count=%d rtd.max=%d\n", 
		atomic_read(&result_counter[0]), 
		atomic_read(&result_counter[1]), 
		atomic_read(&result_counter[2]),
		atomic_read(&result_counter[3]), 
		atomic_read(&result_counter[4]), 
		atomic_read(&result_counter[5])
		);
	return 0;
}

static const struct seq_operations httprtt_seq_ops = {
	.start  = m_start,
	.next   = m_next,
	.stop   = m_stop,
	.show   = m_show,
};

static int httprtt_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &httprtt_seq_ops);
}

static int conf_seq_show(struct seq_file *m, void *v)
{
	seq_printf(m,
			"dolog=%lu, simdrop=%lu, port=%d, ttfb.threshold=%lu(ms), rtd.threshold=%lu(ms)\n",
			conf_dolog, conf_simdrop, conf_port, conf_threshold_ttfb, conf_threshold_rtd);
	return 0;
}
static int conf_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, conf_seq_show, NULL);
}

static char* strtok(char *p)
{
	static char *ptr=0;
	char *result=0;
	
	if(p) ptr=p;

	while(*ptr && *ptr==' '){
		ptr++;
	}

	result=ptr;
	while(*ptr && *ptr!=' '){
		ptr++;
	}
	if(*ptr){
		*ptr=0;
		ptr++;
	}

	return result;
}

static ssize_t conf_seq_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{
#define MAXLEN 40
#define ERRRET(c) if(c){printk(KERN_ERR "Invalid Input\n");return -EINVAL;}

	int rc;
	char *result=0;
	char flags_string[MAXLEN+1];
	unsigned int flags;
	
	if ((count < 1) || (count > MAXLEN))
		return -EINVAL;

	memset(flags_string, 0, MAXLEN+1);

	if (copy_from_user(flags_string, buffer, count))
		return -EFAULT;

	result = strtok(flags_string);
	ERRRET(!result);
	rc = kstrtouint(result, 0, &flags);
	ERRRET(rc);
	conf_dolog=flags;
	
	result = strtok(0);
	ERRRET(!result);
	rc = kstrtouint(result, 0, &flags);
	ERRRET(rc);
	conf_simdrop=flags;
	
	result = strtok(0);
	ERRRET(!result);
	rc = kstrtouint(result, 0, &flags);
	ERRRET(rc);
	conf_port=flags;
	
	result = strtok(0);
	ERRRET(!result);
	rc = kstrtouint(result, 0, &flags);
	ERRRET(rc);
	conf_threshold_ttfb=flags;

	result = strtok(0);
	ERRRET(!result);
	rc = kstrtouint(result, 0, &flags);
	ERRRET(rc);
	conf_threshold_rtd=flags;

	return count;
}

static const struct file_operations httprtt_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = httprtt_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

static const struct file_operations conf_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = conf_seq_open,
	.read	 = seq_read,
	.write	 = conf_seq_write,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static int __init nf_conntrack_httprtt_init(void)
{
	int ret = 0;
	struct proc_dir_entry *pde;

	printk(KERN_ERR "nf_ct_httprtt: init, HZ=%d\n", HZ);
	//httprtt.tuple.dst.u.tcp.port = cpu_to_be16(conf_port);
	ret = nf_conntrack_helper_register(&httprtt);
	if (ret) {
		printk(KERN_ERR "nf_ct_httprtt: failed to register");
		nf_conntrack_httprtt_fini();
		return ret;
	}

	pde = proc_create("httprtt", S_IRUGO,
			  init_net.proc_net, &httprtt_seq_fops);
	if (!pde)
		return -1;

	pde = proc_create("httprtt_conf", S_IRWXUGO,
			  init_net.proc_net, &conf_seq_fops);
	if (!pde)
		return -1;

	return 0;
}

module_init(nf_conntrack_httprtt_init);
module_exit(nf_conntrack_httprtt_fini);
