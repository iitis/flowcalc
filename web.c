/*
 * web - HTTP/HTTPS/SPDY web application traffic analyzer
 *
 * Author: Paweł Foremski
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#include <arpa/inet.h>
#include "flowcalc.h"

#define GROUP_TIME 5.0
#define RESPONSE_TIME 5.0

struct flow {
	enum {
		STATE_NONE = 0,
		STATE_ASKING,
		STATE_RESPONDING
	} connstate;
	double ts_asked;
	double ts_responded;
	double last_query;

	struct dstats {
		uint32_t cnt;

		enum {
			STATE_EMPTY = 0,
			STATE_STARTED_TLS_APP,
			STATE_IGNORE
		} segstate;
		uint32_t seglen;

		uint32_t size_50;
		uint32_t size_100;
		uint32_t size_150;
		uint32_t size_200;
		uint32_t size_300;
		uint32_t size_400;
		uint32_t size_500;
		uint32_t size_600;
		uint32_t size_700;
		uint32_t size_800;
		uint32_t size_900;
		uint32_t size_1000;
		uint32_t size_1200;
		uint32_t size_1400;
		uint32_t size_1600;
		uint32_t size_1800;
		uint32_t size_2000;
		uint32_t size_3000;
		uint32_t size_4000;
		uint32_t size_5000;
		uint32_t size_10000;
		uint32_t size_max;

		uint32_t time_10;
		uint32_t time_50;
		uint32_t time_100;
		uint32_t time_200;
		uint32_t time_500;
		uint32_t time_1000;
		uint32_t time_2500;
		uint32_t time_5000;
	} up;

	struct dstats down;
};

bool init()
{
	printf("%%%% web 0.1\n");
	printf("%% web_up_size_50:     [up] request size probability:    <50 B\n");
	printf("%% web_up_size_100:    [up] request size probability:   <100\n");
	printf("%% web_up_size_150:    [up] request size probability:   <150\n");
	printf("%% web_up_size_200:    [up] request size probability:   <200\n");
	printf("%% web_up_size_300:    [up] request size probability:   <300\n");
	printf("%% web_up_size_400:    [up] request size probability:   <400\n");
	printf("%% web_up_size_500:    [up] request size probability:   <500\n");
	printf("%% web_up_size_600:    [up] request size probability:   <600\n");
	printf("%% web_up_size_700:    [up] request size probability:   <700\n");
	printf("%% web_up_size_800:    [up] request size probability:   <800\n");
	printf("%% web_up_size_900:    [up] request size probability:   <900\n");
	printf("%% web_up_size_1000:   [up] request size probability:  <1000\n");
	printf("%% web_up_size_1200:   [up] request size probability:  <1200\n");
	printf("%% web_up_size_1400:   [up] request size probability:  <1400\n");
	printf("%% web_up_size_1600:   [up] request size probability:  <1600\n");
	printf("%% web_up_size_1800:   [up] request size probability:  <1800\n");
	printf("%% web_up_size_2000:   [up] request size probability:  <2000\n");
	printf("%% web_up_size_3000:   [up] request size probability:  <3000\n");
	printf("%% web_up_size_4000:   [up] request size probability:  <4000\n");
	printf("%% web_up_size_5000:   [up] request size probability:  <5000\n");
	printf("%% web_up_size_10000:  [up] request size probability: <10000\n");
	printf("%% web_up_size_max:    [up] request size probability:>=10000\n");
	printf("%% web_up_query_10:    [up] time between queries:        <10 ms\n");
	printf("%% web_up_query_50:    [up] time between queries:        <50\n");
	printf("%% web_up_query_100:   [up] time between queries:       <100\n");
	printf("%% web_up_query_200:   [up] time between queries:       <200\n");
	printf("%% web_up_query_500:   [up] time between queries:       <500\n");
	printf("%% web_up_query_1000:  [up] time between queries:      <1000\n");
	printf("%% web_up_query_2500:  [up] time between queries:      <2500\n");
	printf("%% web_up_query_5000:  [up] time between queries:      <5000\n");

	printf("%% web_down_size_* ...\n");
	printf("%% web_down_resp_10:   [down] response time:             <10 ms\n");
	printf("%% web_down_resp_50:   [down] response time:             <50\n");
	printf("%% web_down_resp_100:  [down] response time:            <100\n");
	printf("%% web_down_resp_200:  [down] response time:            <200\n");
	printf("%% web_down_resp_500:  [down] response time:            <500\n");
	printf("%% web_down_resp_1000: [down] response time:           <1000\n");
	printf("%% web_down_resp_2500: [down] response time:           <2500\n");
	printf("%% web_down_resp_5000: [down] response time:           <5000\n");

	printf("@attribute web_up_size_50 numeric\n");
	printf("@attribute web_up_size_100 numeric\n");
	printf("@attribute web_up_size_150 numeric\n");
	printf("@attribute web_up_size_200 numeric\n");
	printf("@attribute web_up_size_300 numeric\n");
	printf("@attribute web_up_size_400 numeric\n");
	printf("@attribute web_up_size_500 numeric\n");
	printf("@attribute web_up_size_600 numeric\n");
	printf("@attribute web_up_size_700 numeric\n");
	printf("@attribute web_up_size_800 numeric\n");
	printf("@attribute web_up_size_900 numeric\n");
	printf("@attribute web_up_size_1000 numeric\n");
	printf("@attribute web_up_size_1200 numeric\n");
	printf("@attribute web_up_size_1400 numeric\n");
	printf("@attribute web_up_size_1600 numeric\n");
	printf("@attribute web_up_size_1800 numeric\n");
	printf("@attribute web_up_size_2000 numeric\n");
	printf("@attribute web_up_size_3000 numeric\n");
	printf("@attribute web_up_size_4000 numeric\n");
	printf("@attribute web_up_size_5000 numeric\n");
	printf("@attribute web_up_size_10000 numeric\n");
	printf("@attribute web_up_size_max numeric\n");

	printf("@attribute web_up_query_10 numeric\n");
	printf("@attribute web_up_query_50 numeric\n");
	printf("@attribute web_up_query_100 numeric\n");
	printf("@attribute web_up_query_200 numeric\n");
	printf("@attribute web_up_query_500 numeric\n");
	printf("@attribute web_up_query_1000 numeric\n");
	printf("@attribute web_up_query_2500 numeric\n");
	printf("@attribute web_up_query_5000 numeric\n");

	printf("@attribute web_down_size_50 numeric\n");
	printf("@attribute web_down_size_100 numeric\n");
	printf("@attribute web_down_size_150 numeric\n");
	printf("@attribute web_down_size_200 numeric\n");
	printf("@attribute web_down_size_300 numeric\n");
	printf("@attribute web_down_size_400 numeric\n");
	printf("@attribute web_down_size_500 numeric\n");
	printf("@attribute web_down_size_600 numeric\n");
	printf("@attribute web_down_size_700 numeric\n");
	printf("@attribute web_down_size_800 numeric\n");
	printf("@attribute web_down_size_900 numeric\n");
	printf("@attribute web_down_size_1000 numeric\n");
	printf("@attribute web_down_size_1200 numeric\n");
	printf("@attribute web_down_size_1400 numeric\n");
	printf("@attribute web_down_size_1600 numeric\n");
	printf("@attribute web_down_size_1800 numeric\n");
	printf("@attribute web_down_size_2000 numeric\n");
	printf("@attribute web_down_size_3000 numeric\n");
	printf("@attribute web_down_size_4000 numeric\n");
	printf("@attribute web_down_size_5000 numeric\n");
	printf("@attribute web_down_size_10000 numeric\n");
	printf("@attribute web_down_size_max numeric\n");

	printf("@attribute web_down_resp_10 numeric\n");
	printf("@attribute web_down_resp_50 numeric\n");
	printf("@attribute web_down_resp_100 numeric\n");
	printf("@attribute web_down_resp_200 numeric\n");
	printf("@attribute web_down_resp_500 numeric\n");
	printf("@attribute web_down_resp_1000 numeric\n");
	printf("@attribute web_down_resp_2500 numeric\n");
	printf("@attribute web_down_resp_5000 numeric\n");

	return true;
}

/** Check if packet holds TLS application data */
static bool is_tls_app(libtrace_packet_t *pkt)
{
	uint8_t proto;
	uint16_t ethertype;
	uint32_t rem;
	void *ptr;
	uint8_t *v;
	int i, j;

	ptr = trace_get_layer3(pkt, &ethertype, &rem);
	if (!ptr || ethertype != TRACE_ETHERTYPE_IP)
		return false;

	ptr = trace_get_payload_from_ip(ptr, &proto, &rem);
	if (!ptr || proto != TRACE_IPPROTO_TCP)
		return false;

	v = trace_get_payload_from_tcp(ptr, &rem);
	if (!v || rem < 5)
		return false;

	i = 0;
	while (i < rem) {
		/* TLS major version must be 3 */
		if (v[i+1] != 3)
			return false;

		/* TLS minor version must be <= 3 */
		if (v[i+2] > 3)
			return false;

		/* check TLS Record Layer Protocol Type */
		switch (v[i]) {
			case 0x14: /* ChangeCipherSpec */
			case 0x15: /* Alert */
			case 0x16: /* Handshake */
				break;
			case 0x17: /* Application */
				return true;
			default:   /* not TLS? */
				return false;
		}

		/* read the length and jump to next record */
		j = v[i+3];
		j = (j << 16) + v[i+4];
		if (j > 16384)
			return false;

		i += j + 5;
	}

	return false;
}

static void time_register(struct dstats *s, double time)
{
	if (time < 0.01)
		s->time_10++;
	else if (time < 0.05)
		s->time_50++;
	else if (time < 0.1)
		s->time_100++;
	else if (time < 0.2)
		s->time_200++;
	else if (time < 0.5)
		s->time_500++;
	else if (time < 1.0)
		s->time_1000++;
	else if (time < 2.5)
		s->time_2500++;
	else if (time < 5.0)
		s->time_5000++;
}

void pkt(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	struct flow *f = data;
	int len;
	struct dstats *s;
	libtrace_tcp_t *tcp;
	double diff;

	tcp = trace_get_tcp(pkt);
	if (!tcp)
		return;

	/* correct "up" */
	up = (ntohs(tcp->source) > ntohs(tcp->dest));

	if (up)
		s = &(f->up);
	else
		s = &(f->down);

	/* ignore packets with no data */
	len = trace_get_payload_length(pkt);
	if (len == 0)
		return;

	/* add packet size to current segment */
	s->seglen += len;
	switch (s->segstate) {
		case STATE_EMPTY:
			if (is_tls_app(pkt)) {
				s->segstate = STATE_STARTED_TLS_APP;
				/* NB: fall-through */
			} else {
				s->segstate = STATE_IGNORE;
				return;
			}
		case STATE_STARTED_TLS_APP:
			if (tcp->psh)
				break;  /* take it */
			else
				return; /* buffer */
		case STATE_IGNORE:
			if (tcp->psh)
				goto segment_finished;
			else
				return;
	}

	/*
	 * accepted
	 */
	s->cnt++;

	/* detect connection state */
	switch (f->connstate) {
		case STATE_NONE:
			if (up) {
				f->ts_asked = ts;
				f->connstate = STATE_ASKING;
			} else {
				f->ts_responded = ts;
				f->connstate = STATE_RESPONDING;
			}
			break;
		case STATE_ASKING:
			if (up) { /* =packet was sent to server */
				diff = ts - f->ts_asked;

				/* track group of queries */
				if (diff > GROUP_TIME) {
					/* treat as another group */
					f->ts_asked = ts;
				} else {
					f->ts_asked = (f->ts_asked + ts) / 2.0;
				}
			} else { /* =packet was sent from server */
				if (f->last_query > 0) {
					diff = f->ts_asked - f->last_query;

					/* track group of queries */
					if (diff < GROUP_TIME)
						time_register(&(f->up), diff);
				}
				f->last_query = f->ts_asked;

				f->connstate = STATE_RESPONDING;
				f->ts_responded = ts;
			}
			break;
		case STATE_RESPONDING:
			if (!up) { /* =packet was sent from server */
				diff = ts - f->ts_responded;

				if (diff < RESPONSE_TIME)
					f->ts_responded = (f->ts_responded + ts) / 2.0;
			} else { /* =packet was sent to server */
				diff = f->ts_responded - f->ts_asked;

				if (diff < RESPONSE_TIME)
					time_register(&(f->down), diff);

				f->connstate = STATE_ASKING;
				f->ts_asked = ts;
			}
			break;
	}

	/* put into the size histogram */
	if (s->seglen < 50)
		s->size_50++;
	else if (s->seglen < 100)
		s->size_100++;
	else if (s->seglen < 150)
		s->size_150++;
	else if (s->seglen < 200)
		s->size_200++;
	else if (s->seglen < 300)
		s->size_300++;
	else if (s->seglen < 400)
		s->size_400++;
	else if (s->seglen < 500)
		s->size_500++;
	else if (s->seglen < 600)
		s->size_600++;
	else if (s->seglen < 700)
		s->size_700++;
	else if (s->seglen < 800)
		s->size_800++;
	else if (s->seglen < 900)
		s->size_900++;
	else if (s->seglen < 1000)
		s->size_1000++;
	else if (s->seglen < 1200)
		s->size_1200++;
	else if (s->seglen < 1400)
		s->size_1400++;
	else if (s->seglen < 1600)
		s->size_1600++;
	else if (s->seglen < 1800)
		s->size_1800++;
	else if (s->seglen < 2000)
		s->size_2000++;
	else if (s->seglen < 3000)
		s->size_3000++;
	else if (s->seglen < 4000)
		s->size_4000++;
	else if (s->seglen < 5000)
		s->size_5000++;
	else if (s->seglen < 10000)
		s->size_10000++;
	else
		s->size_max++;

segment_finished:
	s->seglen = 0;
	s->segstate = STATE_EMPTY;
}

void flow(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data)
{
	struct flow *f = data;
	struct dstats *s;

	for (s = &(f->up);;) {
		if (s->cnt == 0) {
			printf(",0,0,0,0,0,0,0,0,0,0");
			printf(",0,0,0,0,0,0,0,0,0,0");
			printf(",0,0");

			printf(",0,0,0,0,0,0,0,0");
		} else {
			printf(",%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f",
				(double) s->size_50  / s->cnt, (double) s->size_100 / s->cnt,
				(double) s->size_150 / s->cnt, (double) s->size_200 / s->cnt,
				(double) s->size_300 / s->cnt, (double) s->size_400 / s->cnt,
				(double) s->size_500 / s->cnt, (double) s->size_600 / s->cnt,
				(double) s->size_700 / s->cnt, (double) s->size_800 / s->cnt);

			printf(",%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f",
				(double) s->size_900  / s->cnt, (double) s->size_1000 / s->cnt,
				(double) s->size_1200 / s->cnt, (double) s->size_1400 / s->cnt,
				(double) s->size_1600 / s->cnt, (double) s->size_1800 / s->cnt,
				(double) s->size_2000 / s->cnt, (double) s->size_3000 / s->cnt,
				(double) s->size_4000 / s->cnt, (double) s->size_5000 / s->cnt);

			printf(",%.3f,%.3f",
				(double) s->size_10000 / s->cnt, (double) s->size_max / s->cnt);

			printf(",%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f",
				(double) s->time_10  / s->cnt,  (double) s->time_50   / s->cnt,
				(double) s->time_100 / s->cnt,  (double) s->time_200  / s->cnt,
				(double) s->time_500 / s->cnt,  (double) s->time_1000 / s->cnt,
				(double) s->time_2500 / s->cnt, (double) s->time_5000 / s->cnt);
		}

		if (s == &(f->up))
			s = &(f->down);
		else
			break;
	}
}

struct module module = {
	.size = sizeof(struct flow),
	.init = init,
	.pkt  = pkt,
	.flow = flow
};
