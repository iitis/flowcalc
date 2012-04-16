/*
 * basic_stats - basic packet length and inter-arrival time statistics
 *
 * Author: Paweł Foremski
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#include <math.h>
#include "flowcalc.h"

struct stats {
	uint64_t pkts;

	uint16_t pktlen_min;
	uint16_t pktlen_max;
	double pktlen_mean;
	double pktlen_std;

	double last_ts;
	uint32_t iat_min;
	uint32_t iat_max;
	double iat_mean;
	double iat_std;
};

struct flow {
	struct stats up;
	struct stats down;
};

/*****************************/

bool init()
{
	printf("%%%% basic_stats 0.1\n");
	printf("%% bs_min_size_up: minimum payload size in forward direction\n");
	printf("%% bs_avg_size_up: average payload size in forward direction\n");
	printf("%% bs_max_size_up: maximum payload size in forward direction\n");
	printf("%% bs_std_size_up: standard deviation of payload size in forward direction\n");
	printf("%% bs_min_size_down: minimum payload size in backward direction\n");
	printf("%% bs_avg_size_down: average payload size in backward direction\n");
	printf("%% bs_max_size_down: maximum payload size in backward direction\n");
	printf("%% bs_std_size_down: standard deviation of payload size in backward direction\n");
	printf("%% bs_min_iat_up: minimum inter-arrival time in forward direction\n");
	printf("%% bs_avg_iat_up: average inter-arrival time in forward direction\n");
	printf("%% bs_max_iat_up: maximum inter-arrival time in forward direction\n");
	printf("%% bs_std_iat_up: standard deviation of inter-arrival time in forward direction\n");
	printf("%% bs_min_iat_down: minimum inter-arrival time in backward direction\n");
	printf("%% bs_avg_iat_down: average inter-arrival time in backward direction\n");
	printf("%% bs_max_iat_down: maximum inter-arrival time in backward direction\n");
	printf("%% bs_std_iat_down: standard deviation of inter-arrival time in backward direction\n");

	printf("@attribute bs_min_size_up numeric\n");
	printf("@attribute bs_avg_size_up numeric\n");
	printf("@attribute bs_max_size_up numeric\n");
	printf("@attribute bs_std_size_up numeric\n");
	printf("@attribute bs_min_size_down numeric\n");
	printf("@attribute bs_avg_size_down numeric\n");
	printf("@attribute bs_max_size_down numeric\n");
	printf("@attribute bs_std_size_down numeric\n");
	printf("@attribute bs_min_iat_up numeric\n");
	printf("@attribute bs_avg_iat_up numeric\n");
	printf("@attribute bs_max_iat_up numeric\n");
	printf("@attribute bs_std_iat_up numeric\n");
	printf("@attribute bs_min_iat_down numeric\n");
	printf("@attribute bs_avg_iat_down numeric\n");
	printf("@attribute bs_max_iat_down numeric\n");
	printf("@attribute bs_std_iat_down numeric\n");

	return true;
}

void pkt(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	struct flow *flow = data;
	struct stats *is;
	int pktlen;
	uint32_t iat;
	double diff, mean, iatd;

	if (is_new) {
		flow->up.pktlen_min = UINT16_MAX;
		flow->up.iat_min = UINT32_MAX;

		flow->down.pktlen_min = UINT16_MAX;
		flow->down.iat_min = UINT32_MAX;
	}

	is = (up ? &flow->up : &flow->down);
	is->pkts++;

	/* pkt length statistics */
	pktlen = trace_get_payload_length(pkt);
	if (pktlen < is->pktlen_min)
		is->pktlen_min = pktlen;
	if (pktlen > is->pktlen_max)
		is->pktlen_max = pktlen;

	diff = pktlen - is->pktlen_mean;
	mean = is->pktlen_mean + diff / is->pkts;
	is->pktlen_std += diff * (pktlen - mean);
	is->pktlen_mean = mean;

	/* pkt inter-arrival time */
	if (!is_new) {
		iatd = ts - is->last_ts;
		if (iatd < 0) {
			iat = 0;
		} else {
			/* convert to us */
			iatd *= 1000000;

			if (iatd > UINT32_MAX)
				iat = UINT32_MAX;
			else
				iat = iatd;
		}

		if (iat < is->iat_min)
			is->iat_min = iat;
		if (iat > is->iat_max)
			is->iat_max = iat;

		diff = iat - is->iat_mean;
		mean = is->iat_mean + diff / is->pkts;
		is->iat_std += diff * (iat - mean);
		is->iat_mean = mean;
	}

	/* update timestamp of last pkt in this direction */
	is->last_ts = ts;
}

void flow(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data)
{
	struct flow *flow = data;
	struct stats *is;
	int i;

	/* print packet length statistics */
	is = &flow->up;
	for (i = 0; i < 2; i++) {
		if (is->pkts == 0) {
			printf(",0,0,0,0");
		} else {
			printf(",%u,%.0f,%u,%.0f",
				is->pktlen_min, is->pktlen_mean, is->pktlen_max,
				sqrt(is->pktlen_std / is->pkts));
		}
		is = &flow->down;
	}

	/* print inter-arrival time statistics */
	is = &flow->up;
	for (i = 0; i < 2; i++) {
		if (is->pkts == 0) {
			printf(",0,0,0,0");
		} else {
			printf(",%u,%.0f,%u,%.0f",
				is->iat_min, is->iat_mean, is->iat_max,
				sqrt(is->iat_std / is->pkts));
		}
		is = &flow->down;
	}
}

struct module module = {
	.size = sizeof(struct flow),
	.init = init,
	.pkt  = pkt,
	.flow = flow
};
