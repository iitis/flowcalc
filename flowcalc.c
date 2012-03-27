/*
 * flowcalc
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 *
 * Licensed under GNU GPL v. 3
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include <libpjf/main.h>
#include <libflowcalc.h>

#include "flowcalc.h"

void flow_start(struct lfc *lfc, struct lfc_flow *lf, void *data)
{
	printf("%.6f", lf->ts);

	if (lf->proto == IPPROTO_UDP)
		printf(",UDP");
	else
		printf(",TCP");

	printf(",%s,%d", inet_ntoa(lf->src.addr.ip4), lf->src.port);
	printf(",%s,%d", inet_ntoa(lf->dst.addr.ip4), lf->dst.port);
}

void flow_end(struct lfc *lfc, struct lfc_flow *lf, void *data)
{
	printf("\n");
}

int main(int argc, char *argv[])
{
	struct lfc *lfc;
	void *h;
	struct module *mod;

	if (argc < 2) {
		fprintf(stderr, "Usage: flowcalc file.pcap [\"filter\"]\n");
		return 1;
	}

	debug = 5;
	lfc = lfc_init();
	lfc_register(lfc, "flow_start", 0, NULL, flow_start);

	/* TODO:
	 * - generate file header (ARFF/CSV support?)
	 * - support module "init"
	 * - load modules in loop
	 * - read modules to load from command-line
	 */
	printf("# flowcalc: 1st packet timestamp, transport protocol, initializing endpoint, peer endpoint\n");

	/***/

	h = dlopen("./counters.so", RTLD_LOCAL | RTLD_LAZY);
	mod = dlsym(h, "module");
	lfc_register(lfc, mod->name, mod->size, mod->pkt, mod->flow);

	/***/
	lfc_register(lfc, "flow_end", 0, NULL, flow_end);
	lfc_run(lfc, argv[1], argv[2]);

	lfc_deinit(lfc);
	return 0;
}
