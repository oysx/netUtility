//Derived from libxt_udp.c
/* Need to download iptables source code the give the include dir in Makefile
- INSTALL:
	make
	make install
*/
#include <stdint.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <xtables.h>
#include <linux/netfilter/xt_tcpudp.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

enum {
	O_SOURCE_PORT = 0,
	O_DEST_PORT,
};

static void chdst_help(void)
{
	printf(
"CHDST target options:\n"
"[!] --source-port port[:port]\n"
" --sport ...\n"
"				target source port(s)\n"
"[!] --destination-port port[:port]\n"
" --dport ...\n"
"				target destination port(s)\n");
}

#define s struct xt_udp
static const struct xt_option_entry chdst_opts[] = {
	{.name = "source-port", .id = O_SOURCE_PORT, .type = XTTYPE_PORTRC,
	 .flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(s, spts)},
	{.name = "sport", .id = O_SOURCE_PORT, .type = XTTYPE_PORTRC,
	 .flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(s, spts)},
	{.name = "destination-port", .id = O_DEST_PORT, .type = XTTYPE_PORTRC,
	 .flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(s, dpts)},
	{.name = "dport", .id = O_DEST_PORT, .type = XTTYPE_PORTRC,
	 .flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(s, dpts)},
	XTOPT_TABLEEND,
};
#undef s

static void chdst_init(struct xt_entry_target *m)
{
	struct xt_udp *udpinfo = (struct xt_udp *)m->data;

	udpinfo->spts[1] = udpinfo->dpts[1] = 0xFFFF;
}

static void chdst_parse(struct xt_option_call *cb)
{
	struct xt_udp *udpinfo = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_SOURCE_PORT:
		if (cb->invert)
			udpinfo->invflags |= XT_UDP_INV_SRCPT;
		break;
	case O_DEST_PORT:
		if (cb->invert)
			udpinfo->invflags |= XT_UDP_INV_DSTPT;
		break;
	}
}

static const char *
port_to_service(int port)
{
	const struct servent *service;

	if ((service = getservbyport(htons(port), "udp")))
		return service->s_name;

	return NULL;
}

static void
print_port(uint16_t port, int numeric)
{
	const char *service;

	if (numeric || (service = port_to_service(port)) == NULL)
		printf("%u", port);
	else
		printf("%s", service);
}

static void
print_ports(const char *name, uint16_t min, uint16_t max,
	    int invert, int numeric)
{
	const char *inv = invert ? "!" : "";

	if (min != 0 || max != 0xFFFF || invert) {
		printf(" %s", name);
		if (min == max) {
			printf(":%s", inv);
			print_port(min, numeric);
		} else {
			printf("s:%s", inv);
			print_port(min, numeric);
			printf(":");
			print_port(max, numeric);
		}
	}
}

static void
chdst_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
	const struct xt_udp *udp = (struct xt_udp *)target->data;

	printf(" CHDST");
	print_ports("spt", udp->spts[0], udp->spts[1],
		    udp->invflags & XT_UDP_INV_SRCPT,
		    numeric);
	print_ports("dpt", udp->dpts[0], udp->dpts[1],
		    udp->invflags & XT_UDP_INV_DSTPT,
		    numeric);
	if (udp->invflags & ~XT_UDP_INV_MASK)
		printf(" Unknown invflags: 0x%X",
		       udp->invflags & ~XT_UDP_INV_MASK);
}

static void chdst_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_udp *udpinfo = (struct xt_udp *)target->data;

	if (udpinfo->spts[0] != 0
	    || udpinfo->spts[1] != 0xFFFF) {
		if (udpinfo->invflags & XT_UDP_INV_SRCPT)
			printf(" !");
		if (udpinfo->spts[0]
		    != udpinfo->spts[1])
			printf(" --sport %u:%u",
			       udpinfo->spts[0],
			       udpinfo->spts[1]);
		else
			printf(" --sport %u",
			       udpinfo->spts[0]);
	}

	if (udpinfo->dpts[0] != 0
	    || udpinfo->dpts[1] != 0xFFFF) {
		if (udpinfo->invflags & XT_UDP_INV_DSTPT)
			printf(" !");
		if (udpinfo->dpts[0]
		    != udpinfo->dpts[1])
			printf(" --dport %u:%u",
			       udpinfo->dpts[0],
			       udpinfo->dpts[1]);
		else
			printf(" --dport %u",
			       udpinfo->dpts[0]);
	}
}

static int chdst_xlate(struct xt_xlate *xl,
		     const struct xt_xlate_tg_params *params)
{
	const struct xt_udp *udpinfo = (struct xt_udp *)params->target->data;
	char *space= "";

	if (udpinfo->spts[0] != 0 || udpinfo->spts[1] != 0xFFFF) {
		if (udpinfo->spts[0] != udpinfo->spts[1]) {
			xt_xlate_add(xl,"CHDST sport %s%u-%u",
				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
					 "!= ": "",
				   udpinfo->spts[0], udpinfo->spts[1]);
		} else {
			xt_xlate_add(xl, "CHDST sport %s%u",
				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
					 "!= ": "",
				   udpinfo->spts[0]);
		}
		space = " ";
	}

	if (udpinfo->dpts[0] != 0 || udpinfo->dpts[1] != 0xFFFF) {
		if (udpinfo->dpts[0]  != udpinfo->dpts[1]) {
			xt_xlate_add(xl,"%sCHDST dport %s%u-%u", space,
				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
					 "!= ": "",
				   udpinfo->dpts[0], udpinfo->dpts[1]);
		} else {
			xt_xlate_add(xl,"%sCHDST dport %s%u", space,
				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
					 "!= ": "",
				   udpinfo->dpts[0]);
		}
	}

	return 1;
}

static struct xtables_target chdst_match[] = {{
	.family		= NFPROTO_IPV4,
	.name		= "CHDST",
	.revision = 0,
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_udp)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_udp)),
	.help		= chdst_help,
	.init		= chdst_init,
	.print		= chdst_print,
	.save		= chdst_save,
	.x6_parse	= chdst_parse,
	.x6_options	= chdst_opts,
	.xlate		= chdst_xlate,
}};

void
_init(void)
{
	xtables_register_targets(chdst_match, ARRAY_SIZE(chdst_match));
}
