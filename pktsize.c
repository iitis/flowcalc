/*
 * pktsize - reports packet sizes on first few packets
 *
 * Author: Paweł Foremski
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#include "flowcalc.h"

struct flow {
	struct pks {
		int cnt;
		int size[5];
	} up;

	struct pks down;
};

void header()
{
	printf("%%%% pktsize 0.1\n");

	printf("%% pks_1_up:       size of 1st packet up\n");
	printf("%% pks_2_up:       size of 2nd packet up\n");
	printf("%% pks_3_up:       size of 3rd packet up\n");
	printf("%% pks_4_up:       size of 4th packet up\n");
	printf("%% pks_5_up:       size of 5th packet up\n");
	printf("%% pks_1_down:     size of 1st packet down\n");
	printf("%% pks_2_down:     size of 2nd packet down\n");
	printf("%% pks_3_down:     size of 3rd packet down\n");
	printf("%% pks_4_down:     size of 4th packet down\n");
	printf("%% pks_5_down:     size of 5th packet down\n");

	printf("@attribute pks_1_up numeric\n");
	printf("@attribute pks_2_up numeric\n");
	printf("@attribute pks_3_up numeric\n");
	printf("@attribute pks_4_up numeric\n");
	printf("@attribute pks_5_up numeric\n");
	printf("@attribute pks_1_down numeric\n");
	printf("@attribute pks_2_down numeric\n");
	printf("@attribute pks_3_down numeric\n");
	printf("@attribute pks_4_down numeric\n");
	printf("@attribute pks_5_down numeric\n");
}

void pkt(struct lfc *lfc, void *plugin,
	struct lfc_flow *lf, struct lfc_pkt *pkt, void *data)
{
	struct flow *f = data;

	/* done? */
	if (pkt->up) {
		if (f->up.cnt == 5) return;
	} else {
		if (f->down.cnt == 5) return;
	}

	/* packet useful? */
	if (pkt->dup || pkt->psize == 0) return;

	/* record! */
	if (pkt->up) {
		f->up.size[f->up.cnt++] = pkt->psize;
	} else {
		f->down.size[f->down.cnt++] = pkt->psize;
	}
}

void flow(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data)
{
	struct flow *f = data;

	printf(",%d,%d,%d,%d,%d",
		f->up.size[0], f->up.size[1], f->up.size[2],
		f->up.size[3], f->up.size[4]);

	printf(",%d,%d,%d,%d,%d",
		f->down.size[0], f->down.size[1], f->down.size[2],
		f->down.size[3], f->down.size[4]);
}

struct module module = {
	.size = sizeof(struct flow),
	.header = header,
	.pkt  = pkt,
	.flow = flow
};
