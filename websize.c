/*
 * websize: reports packet sizes for beginning of HTTPS connection
 * Copyright (C) 2015 Akamai Technologies, Inc. <http://www.akamai.com/>
 * Copyright (c) 2015 IITiS PAN Gliwice <http://www.iitis.pl/>
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
static bool is_tls_data(struct lfc_pkt *pkt)
{
	/* packet is useful? */
	if (!pkt->tcp) return false;
	if (!pkt->data) return false;
	if (pkt->len < 3) return false;

	/* check TLS */
	uint8_t *v = pkt->data;
	if (v[0] != 0x17)  return false; /* TLS Protocol Type must be Application */
	if (v[1] != 3)     return false; /* TLS major version must be 3 */
	if (v[2] > 3)      return false; /* TLS minor version must be <= 3 */

	return true;
}

void pkt(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, struct lfc_pkt *pkt, void *data)
{
	struct flow *f = data;
	struct pks *s = pkt->up ? &(f->up) : &(f->down);

	if (pkt->dup) return;

	/* do we still need stats? */
	if (s->cnt == N(s->size)) return;

	/* skip no-payloads */
	if (pkt->psize < 5) return;

	/* skip SSL setup */
	if (!s->indata) {
		if (is_tls_data(pkt))
			s->indata = true;
		else
			return;
	}

	/* ignore non-DATA frames (SPDY/H2) */
	if (pkt->psize < 80) return;

	/* count it */
	s->size[s->cnt++] = pkt->psize;
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
