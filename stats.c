/*
 * stats - basic packet length and inter-arrival time statistics
 *
 * Author: Paweł Foremski
 * Copyright (c) 2012-2015 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#include <math.h>
#include "flowcalc.h"

struct stats {
	uint64_t pkts;

	uint16_t pktlen_min;
	uint16_t pktlen_max;
	double pktlen_mean;
	double pktlen_var;

	double last_ts;
	double iat_min;
	double iat_max;
	double iat_mean;
	double iat_var;
};

struct flow {
	struct stats up;
	struct stats down;
};

/*****************************/

void header()
{
	printf("%%%% stats 0.1\n");
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
}

void pkt(struct lfc *lfc, void *plugin,
	struct lfc_flow *lf, struct lfc_pkt *pkt, void *data)
{
	struct flow *flow = data;
	struct stats *is;
	double iat, n;

	if (pkt->first) {
		flow->up.pktlen_min = UINT16_MAX;
		flow->down.pktlen_min = UINT16_MAX;
		flow->up.iat_min = -1;
		flow->down.iat_min = -1;
	}

	if (pkt->dup) return;
	if (pkt->psize == 0) return;

	is = (pkt->up ? &flow->up : &flow->down);
	is->pkts++;
	n = is->pkts;

	/*
	 * payload length statistics
	 */
	if (pkt->psize < is->pktlen_min) is->pktlen_min = pkt->psize;
	if (pkt->psize > is->pktlen_max) is->pktlen_max = pkt->psize;

	if (n > 1)
		is->pktlen_var = (n-2)/(n-1)*is->pktlen_var + 1/n*pow(pkt->psize - is->pktlen_mean, 2.);
	is->pktlen_mean = (pkt->psize + (n-1)*is->pktlen_mean) / n;

	/*
	 * payload packet inter-arrival time stats
	 */
	if (is->last_ts > 0 && pkt->ts > is->last_ts) {
		iat = (pkt->ts - is->last_ts) * 1000.;

		if (is->iat_min < 0 || iat < is->iat_min) is->iat_min = iat;
		if (iat > is->iat_max) is->iat_max = iat;

		if (n > 1)
			is->iat_var = (n-2)/(n-1)*is->iat_var + 1/n*pow(iat - is->iat_mean, 2.);
		is->iat_mean = (iat + (n-1)*is->iat_mean) / n;
	}

	/* update timestamp of last pkt in this direction */
	is->last_ts = pkt->ts;
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
				is->pktlen_min, is->pktlen_mean, is->pktlen_max, sqrt(is->pktlen_var));
		}
		is = &flow->down;
	}

	/* print inter-arrival time statistics */
	is = &flow->up;
	for (i = 0; i < 2; i++) {
		if (is->pkts < 2) {
			printf(",0,0,0,0");
		} else {
			printf(",%.0f,%.0f,%.0f,%.0f",
				is->iat_min, is->iat_mean, is->iat_max, sqrt(is->iat_var / is->pkts));
		}
		is = &flow->down;
	}
}

struct module module = {
	.size = sizeof(struct flow),
	.header = header,
	.pkt  = pkt,
	.flow = flow
};
