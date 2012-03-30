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

bool init()
{
	printf("%%%% counters 0.1\n");
	printf("%% cts_pkts_up:    number of packets in the initial direction\n");
	printf("%% cts_pkts_down:  number of packets backwards\n");
	printf("%% cts_bytes_up:   number of bytes in the initial direction\n");
	printf("%% cts_bytes_down: numbers of bytes backwards\n");

	printf("@attribute cts_pkts_up numeric\n");
	printf("@attribute cts_pkts_down numeric\n");
	printf("@attribute cts_bytes_up numeric\n");
	printf("@attribute cts_bytes_down numeric\n");

	return true;
}

void pkt(struct lfc *lfc, void *pdata,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt, void *data)
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

void flow(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data)
{
	struct flow *t = data;

	printf(",%d,%d", t->pkts_up, t->pkts_down);
	printf(",%d,%d", t->bytes_up, t->bytes_down);
}

struct module module = {
	.size = sizeof(struct flow),
	.init = init,
	.pkt  = pkt,
	.flow = flow
};
