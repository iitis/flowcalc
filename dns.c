/*
 * dns - find DNS name associated with a flow
 *
 * Author: Paweł Foremski
 * Copyright (c) 2013 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libtrace.h>

#include <libpjf/lib.h>
#include "flowcalc.h"

/* store DNS for 10h */
#define DNS_BACKLOG 36000.0

struct client {
	double ts;                     /**> last update timestamp */
	thash *servers;                /**> names for servers: (uint32_t dst_ip) -> (char *) DNS name */
};

struct dnsdata {
	mmatic *mm;                    /**> memory manager */
	thash *clients;                /**> client tracking: (uint32_t src_ip) -> (struct client *) */
	double gcstamp;                /**> timestamp for next garbage collector run */
};

struct flowdata {
	bool is_dns;                   /**> can it be a DNS flow? */
	bool dns_found;                /**> DNS reply found? */
	char name[64];                 /**> flow DNS name */
};

/**************************** utility functions */
void free_client(void *ptr)
{
	struct client *client = ptr;
	thash_free(client->servers);
}
struct client *create_client(mmatic *mm)
{
	struct client *client;
	client = mmatic_zalloc(mm, sizeof *client);
	client->servers = thash_create_intkey(mmatic_free, mm);
	return client;
}

bool is_dns(struct lfc_flow *flow)
{
	if (flow->proto != IPPROTO_UDP)
		return false;
	if (flow->src.port != 53 && flow->dst.port != 53)
		return false;

	return true;
}
const char *parse_labels(uint8_t *buf, int rem, int *len)
{
	int i;
	uint8_t ll;
	static char name[512];
	char *nptr = name;

	if (rem <= 0 || rem > 512) return NULL;

	name[0] = 0;
	*len = 0;

	while (true) {
		ll = buf[0];
		if (ll == 0) {
			*len += 1;
			break;
		} else if (ll == 0xc0) {
			*len += 2;
			break;
		}

#define BUF_MOVE(l) \
		{ buf += (l); rem -= (l); *len += (l); if (rem <= 0) return NULL; }

		BUF_MOVE(1);
		for (i = 0; i < ll && i < rem; i++)
			*nptr++ = buf[i];
		*nptr++ = '.';
		BUF_MOVE(ll);
	}

	if (nptr > name) nptr[-1] = 0;
	return name;
}
bool is_interesting(uint16_t type, uint16_t class)
{
	if (class != 1) return false;

	if (type ==  1) return true; /* A */
	if (type == 15) return true; /* MX */

	return false;
}

void gcrun(struct dnsdata *md, double ts)
{
	struct client *cl;
	unsigned long key;
	double min_ts;

	min_ts = ts - DNS_BACKLOG;

	thash_reset(md->clients);
	while ((cl = thash_uint_iter(md->clients, &key))) {
		if (cl->ts < min_ts)
			thash_uint_set(md->clients, key, NULL);
	}

	md->gcstamp = ts + 1800.0; /* run again in 30 minutes */
}

void db_add(struct dnsdata *md, struct in_addr client_addr,
	struct in_addr server_addr, const char *dns_name, double ts)
{
	struct client *cl;

	/* run GC */
	if (!md->gcstamp || ts > md->gcstamp)
		gcrun(md, ts);

	/* get client */
	cl = thash_uint_get(md->clients, client_addr.s_addr);
	if (!cl) {
		cl = create_client(md->mm);
		thash_uint_set(md->clients, client_addr.s_addr, cl);
	}

	/* update DNS binding */
	thash_uint_set(cl->servers, server_addr.s_addr, mmatic_strdup(md->mm, dns_name));
	cl->ts = ts;
}

/** Find DNS name for given flow */
const char *find_name(struct dnsdata *md, struct in_addr client_addr, struct in_addr server_addr)
{
	struct client *cl;

	cl = thash_uint_get(md->clients, client_addr.s_addr);
	if (!cl)
		return NULL;

	return thash_uint_get(cl->servers, server_addr.s_addr);
}

void flow_assign_name(struct dnsdata *md, struct lfc_flow *flow, struct flowdata *fd)
{
	const char *name;

	name = find_name(md, flow->src.addr.ip4, flow->dst.addr.ip4);
	if (!name)
		name = find_name(md, flow->dst.addr.ip4, flow->src.addr.ip4);

	/* special case: trace collected on local computer? */
	if (!name && thash_count(md->clients) == 1) {
		struct in_addr loop;
		loop.s_addr = htonl(0x7F000001); /* 127.0.0.1 */

		name = find_name(md, loop, flow->dst.addr.ip4);
		if (!name)
			name = find_name(md, loop, flow->src.addr.ip4);
	}

	if (name) {
		strncpy(fd->name, name, sizeof(fd->name));
	} else {
		dbg(3, "dns: no name for flow src=%s ", inet_ntoa(flow->src.addr.ip4));
		dbg(3, "dst=%s\n", inet_ntoa(flow->dst.addr.ip4));
	}
}

/**************************** main code */

void header()
{
	printf("%%%% dns 0.1\n");
	printf("%% dns_flow: is a DNS flow?\n");
	printf("%% dns_name: DNS domain name\n");
	printf("@attribute dns_flow numeric\n");
	printf("@attribute dns_name string\n");
}

bool init(struct lfc *lfc, void **mydata, struct flowcalc *fc)
{
	struct dnsdata *md;

	md = mmatic_zalloc(lfc->mm, sizeof *md);
	md->mm = lfc->mm;
	md->clients = thash_create_intkey(free_client, md->mm);

	*mydata = md;
	return true;
}

void pkt(struct lfc *lfc, void *mydata,
	struct lfc_flow *flow, void *flowdata,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	struct dnsdata *md = mydata;
	struct flowdata *fd = flowdata;

	/*
	 * is the flow a DNS one?
	 */
	if (is_new) {
		fd->is_dns = is_dns(flow);

		if (!fd->is_dns) {
			flow_assign_name(md, flow, fd);
			return;
		}
	} else if (!fd->is_dns) {
		return;
	}

	/*
	 * parse the IP/UDP packet
	 */
	uint16_t ethertype;
	uint32_t rem;
	libtrace_ip_t *ip;
	libtrace_udp_t *udp;
	uint8_t *buf;
	struct in_addr client_addr;

	ip = trace_get_layer3(pkt, &ethertype, &rem);
	if (!ip) return;

	udp = trace_get_udp_from_ip(ip, &rem);
	if (!udp) return;
	if (ntohs(udp->source) != 53) return; /* it is not a DNS response */

	buf = trace_get_payload_from_udp(udp, &rem);
	if (!buf) return;
	if (rem <= 34) return; /* it is too short to contain meaningful data */

	client_addr = ip->ip_dst;

	/*
	 * parse the DNS header
	 */
	uint8_t opcode, qr, rcode;
	uint16_t alen;

	qr     = buf[2] >> 7;
	opcode = (buf[2] >> 3) & 0x0f;
	rcode  = buf[3] & 0x0f;
	alen   = ntohs(*((uint16_t *) (buf + 6)));

	if (!((qr == 1) && (opcode == 0) && (rcode == 0) && (alen > 0)))
		return; /* nothing interesting/supported in this packet */

	/* assume being here is enough to assure it's a DNS reply packet */
	fd->dns_found = true;

	/*
	 * parse the DNS query
	 */
	int len, left;
	char dns_name[512];
	const char *name;
	uint16_t type, class;

	buf += 12; left = rem - 12;
	name = parse_labels(buf, left, &len);
	if (!name) return;    /* truncated? */
	else       strncpy(dns_name, name, sizeof(dns_name));
	buf += len; left -= len;
	if (left < 4) return; /* truncated? */

	type  = ntohs(*((uint16_t *) (buf + 0)));
	class = ntohs(*((uint16_t *) (buf + 2)));
	if (!is_interesting(type, class)) return;
	buf += 4; left -= 4;

	/*
	 * parse the DNS answers
	 */
	int aid;
	uint16_t rdlen;
	struct in_addr server_addr;

	for (aid = 0; aid < alen; aid++) {
		/* ignore labels... */
		if (!parse_labels(buf, left, &len)) return; /* truncated? */
		buf += len; left -= len;
		if (left < 4) return; /* truncated? */

		/* check Type and Class */
		type  = ntohs(*((uint16_t *) (buf + 0)));
		class = ntohs(*((uint16_t *) (buf + 2)));
		buf += 4; left -= 4;

		/* skip TTL */
		buf += 4; left -= 4;
		if (left < 2) return; /* truncated? */

		/* read rdata length */
		rdlen = ntohs(*((uint16_t *) (buf + 0)));
		buf += 2; left -= 2;

		/* is there an IPv4 address in the answer? */
		if (!is_interesting(type, class) || rdlen != 4) {
			/* skip */
			buf += rdlen; left -= rdlen;
			continue;
		}

		/******************************************/
		if (left < rdlen) return; /* truncated? */
		server_addr.s_addr = *((unsigned long *) buf);
		buf += rdlen; left -= rdlen;

		/* add to the database! */
		db_add(mydata, client_addr, server_addr, dns_name, ts);
		dbg(3, "dns: %.6f client=%s ", ts, inet_ntoa(client_addr));
		dbg(3, "server=%s dns_name=%s\n", inet_ntoa(server_addr), dns_name);
	}

	return;

}

void flow(struct lfc *lfc, void *mydata,
	struct lfc_flow *flow, void *flowdata)
{
	struct flowdata *fd = flowdata;

	if (fd->is_dns)
		printf(",1");
	else
		printf(",0");

	if (fd->name[0])
		printf(",%s", fd->name);
	else
		printf(",?dns_name");
}

struct module module = {
	.size = sizeof(struct flowdata),
	.init = init,
	.header = header,
	.pkt  = pkt,
	.flow = flow
};
