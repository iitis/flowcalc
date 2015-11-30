/*
 * ndpi - nDPI / OpenDPI traffic classifier for flowcalc
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Copyright (C) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 */

#include <stddef.h>
#include <stdint.h>
typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
typedef unsigned int u_int;

#include <libndpi/ndpi_api.h>
#include "flowcalc.h"

static char *p2s[] = { NDPI_PROTOCOL_SHORT_STRING };

struct ndpi {
	mmatic *mm;
	thash *ids;
	struct ndpi_detection_module_struct *ndpi;
};

struct flow {
	uint32_t proto;
	struct ndpi_flow_struct *ndpi_flow;
};

/*****/
/* NOTE: it might be necessary to time-out nd->ids entries in order to decrease memory consumption */
static struct ndpi_id_struct *getid(struct ndpi *nd, struct lfc_flow_addr *lfa)
{
	struct ndpi_id_struct *id;

	id = thash_uint_get(nd->ids, (uint32_t) lfa->addr.ip4.s_addr);

	if (!id) {
		id = mmatic_zalloc(nd->mm, ndpi_detection_get_sizeof_ndpi_id_struct());
		thash_uint_set(nd->ids, (uint32_t) lfa->addr.ip4.s_addr, id);
	}

	return id;
}

static void *ma(unsigned long size) { return malloc(size); }
static void db(uint32_t protocol, void *id_struct,
		ndpi_log_level_t log_level, const char *format, ...)
{
	printf("bla\n");
}

/*****/

bool init(struct lfc *lfc, void **pdata)
{
	mmatic *mm;
	struct ndpi *ndpi;
	NDPI_PROTOCOL_BITMASK all;

	mm = mmatic_create();
	ndpi = mmatic_zalloc(mm, sizeof *ndpi);
	ndpi->mm = mm;
	ndpi->ids = thash_create_intkey(NULL, mm); // TODO: null ffn?

	ndpi->ndpi = ndpi_init_detection_module(1000, ma, db); // TODO: 1000?
	if (!ndpi->ndpi) {
		dbg(0, "ndpi_init_detection_module() failed\n");
		return false;
	}

	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(ndpi->ndpi, &all);

	*pdata = ndpi;
	return true;
}

void header()
{
	printf("%%%% ndpi 0.1 - nDPI\n");
	printf("@attribute ndpi_proto string\n");
}

void pkt(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	struct ndpi *nd = pdata;
	struct flow *f = data;
	struct ndpi_id_struct *srcid, *dstid;
	uint8_t *iph;
	uint16_t et;
	uint32_t rem;
	uint64_t time;

	if (!f->ndpi_flow)
		f->ndpi_flow = mmatic_zalloc(nd->mm, ndpi_detection_get_sizeof_ndpi_flow_struct());

	iph = trace_get_layer3(pkt, &et, &rem);
	time = ts * 1000;

	srcid = getid(nd, &lf->src);
	dstid = getid(nd, &lf->dst);

	f->proto = ndpi_detection_process_packet(
		nd->ndpi, f->ndpi_flow, iph, rem, time, srcid, dstid);
}

void flow(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data)
{
	struct flow *f = data;

	printf(",%s", p2s[f->proto]);
	mmatic_free(f->ndpi_flow);
}

struct module module = {
	.size = sizeof(struct flow),
	.init = init,
	.header = header,
	.pkt  = pkt,
	.flow = flow
};
