/*
 * Author: Paweł Foremski
 * Copyright (c) 2013 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#include <ctype.h>
#include <libtrace.h>
#include "flowcalc.h"

#define LEN 32

struct flowdata {
	char up[LEN];              /**> payload data: upload */
	int ups;                   /**> up size */

	char down[LEN];            /**> payload data: download */
	int downs;                 /**> down size */
};

void header()
{
	printf("%%%% payload 0.1\n");
	printf("%% pl_up: payload bytes\n");
	printf("%% pl_down: payload bytes\n");
	printf("@attribute pl_up string\n");
	printf("@attribute pl_down string\n");
}

void pkt(struct lfc *lfc, void *mydata,
	struct lfc_flow *flow, void *flowdata,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	struct flowdata *fd = flowdata;

	if (up) {
		if (fd->ups > 0) return;
	} else {
		if (fd->downs > 0) return;
	}

	/*
	 * get the payload
	 */
	uint8_t proto;
	uint16_t ethertype;
	uint32_t rem;
	void *ptr;
	uint8_t *v;

	ptr = trace_get_layer3(pkt, &ethertype, &rem);
	if (!ptr || ethertype != TRACE_ETHERTYPE_IP) return;

	ptr = trace_get_payload_from_ip(ptr, &proto, &rem);
	if (!ptr) return;

	if (proto == TRACE_IPPROTO_TCP)
		v = trace_get_payload_from_tcp(ptr, &rem);
	else if (proto == TRACE_IPPROTO_UDP)
		v = trace_get_payload_from_udp(ptr, &rem);
	else
		v = NULL;

	if (!v || rem == 0) return;

	/*
	 * copy
	 */
	if (up) {
		fd->ups = MIN(LEN, rem);
		memcpy(fd->up, v, fd->ups);
	} else {
		fd->downs = MIN(LEN, rem);
		memcpy(fd->down, v, fd->downs);
	}
}

static void print_buf(char *v, int s)
{
	int i;

	printf(",'");
	for (i = 0; i < s; i++) {
		if (v[i] == '\'')
			printf("\\'");
		else if (v[i] == '\\')
			printf("\\\\");
		else if (isprint(v[i]))
			putchar(v[i]);
		else
			putchar('.');
	}
	putchar('\'');
}

void flow(struct lfc *lfc, void *mydata,
	struct lfc_flow *flow, void *flowdata)
{
	struct flowdata *fd = flowdata;

	print_buf(fd->up, fd->ups);
	print_buf(fd->down, fd->downs);
}

struct module module = {
	.size = sizeof(struct flowdata),
	.header = header,
	.pkt  = pkt,
	.flow = flow
};
