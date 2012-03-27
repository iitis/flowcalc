/*
 * counters - packet and byte counters
 *
 * Author: Paweł Foremski
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#include "flowcalc.h"

struct flow {
	int pkts_up;
	int pkts_down;

	int bytes_up;
	int bytes_down;
};

void pkt(struct lfc *lfc, double ts, bool up, libtrace_packet_t *pkt, void *data)
{
	struct flow *t = data;
	int len;

	len = trace_get_payload_length(pkt);

	if (up) {
		t->pkts_up++;
		t->bytes_up += len;
	} else {
		t->pkts_down++;
		t->bytes_down += len;
	}
}

void flow(struct lfc *lfc, struct lfc_flow *lf, void *data)
{
	struct flow *t = data;

	printf(",%d,%d", t->pkts_up, t->pkts_down);
	printf(",%d,%d", t->bytes_up, t->bytes_down);
}

struct module module = {
	.name = "counters",
	.size = sizeof(struct flow),
	.pkt  = pkt,
	.flow = flow
};
