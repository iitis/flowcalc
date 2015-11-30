/*
 * counters - packet and byte counters
 *
 * Author: Paweł Foremski
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "flowcalc.h"

struct flow {
	uint64_t pkts_up;
	uint64_t pkts_down;

	uint64_t bytes_up;
	uint64_t bytes_down;
};

void header()
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
}

void pkt(struct lfc *lfc, void *plugin,
	struct lfc_flow *lf, struct lfc_pkt *pkt, void *data)
{
	struct flow *t = data;

	if (pkt->dup) return;

	if (pkt->up) {
		t->pkts_up++;
		t->bytes_up += pkt->psize;
	} else {
		t->pkts_down++;
		t->bytes_down += pkt->psize;
	}
}

void flow(struct lfc *lfc, void *plugin,
	struct lfc_flow *lf, void *data)
{
	struct flow *t = data;

	printf(",%"PRIu64",%"PRIu64, t->pkts_up, t->pkts_down);
	printf(",%"PRIu64",%"PRIu64, t->bytes_up, t->bytes_down);
}

struct module module = {
	.size = sizeof(struct flow),
	.header = header,
	.pkt  = pkt,
	.flow = flow
};
