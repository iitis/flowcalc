/*
 * websize: reports packet sizes for beginning of HTTPS connection
 * Copyright (C) 2015 Akamai Technologies, Inc. <http://www.akamai.com/>
 *
 * Author: Paweł Foremski <pjf@foremski.pl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * NOTE: The assumption here is that NIC is doing TCP offloading, thus the PSH
 * flag on TCP packet effectively writes a packet to the PCAP file. This has
 * some implications with the SSL library doing the secure transport. Usually a
 * PSH flag means the TCP packet closes an SSL data frame (which can be up to
 * 16KB).
 */

#include "flowcalc.h"

struct flow {
	struct pks {
		bool indata;
		int cnt;
		int size[5];
	} up;

	struct pks down;
};

void header()
{
	int i;

	printf("%%%% websize 0.1\n");
	printf("%% wsNup:       size of Nth packet up\n");
	printf("%% wsNdown:     size of Nth packet down\n");

	for (i = 0; i < N(((struct pks*)0)->size); i++)
		printf("@attribute ws%dup numeric\n", i+1);
	for (i = 0; i < N(((struct pks*)0)->size); i++)
		printf("@attribute ws%ddown numeric\n", i+1);
}

/** Check if packet holds TLS application data (just first 2 bytes) */
static bool is_tls_data(libtrace_packet_t *pkt)
{
	uint8_t proto;
	uint16_t et;
	uint32_t rem;
	void *ptr;
	uint8_t *v;

	/* pass IP */
	ptr = trace_get_layer3(pkt, &et, &rem);
	if (!ptr)
		return false;
	else if (et == TRACE_ETHERTYPE_IP)
		ptr = trace_get_payload_from_ip(ptr, &proto, &rem);
	else if (et == TRACE_ETHERTYPE_IPV6)
		ptr = trace_get_payload_from_ip6(ptr, &proto, &rem);
	else
		return false;

	/* pass TCP */
	if (!ptr)
		return false;
	else if (proto == TRACE_IPPROTO_TCP)
		v = trace_get_payload_from_tcp(ptr, &rem);
	else
		return false;

	/* check TLS */
	if (!v || rem < 3) return false;
	if (v[0] != 0x17)  return false; /* TLS Protocol Type must be Application */
	if (v[1] != 3)     return false; /* TLS major version must be 3 */
	if (v[2] > 3)      return false; /* TLS minor version must be <= 3 */
	return true;
}

void pkt(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	struct flow *f = data;
	struct pks *s = up ? &(f->up) : &(f->down);
	int len;

	/* do we still need stats? */
	if (s->cnt == N(s->size)) return;

	/* skip no-payloads */
	len = trace_get_payload_length(pkt);
	if (len < 5) return;

	/* skip SSL setup */
	if (!s->indata) {
		if (is_tls_data(pkt))
			s->indata = true;
		else
			return;
	}

	/* ignore non-DATA frames (SPDY/H2) */
	if (len < 80) return;

	/* count it */
	s->size[s->cnt++] = len;
}

void flow(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data)
{
	struct flow *f = data;
	int i;

	for (i = 0; i < N(f->up.size); i++) printf(",%d", f->up.size[i]);
	for (i = 0; i < N(f->up.size); i++) printf(",%d", f->down.size[i]);
}

struct module module = {
	.size = sizeof(struct flow),
	.header = header,
	.pkt  = pkt,
	.flow = flow
};
