/*
 * flowcalc: convert PCAP traffic to WEKA files
 * Copyright (C) 2012-2013 IITiS PAN Gliwice <http://www.iitis.pl/>
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
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <time.h>
#include <getopt.h>
#include <stdlib.h>

#include <libpjf/main.h>
#include <libflowcalc.h>

#include "flowcalc.h"

/** Prints usage help screen */
static void help(void)
{
	printf("Usage: flowcalc [OPTIONS] <TRACE FILE>\n");
	printf("\n");
	printf("  Calculates IP flows and their features out of IP trace file (eg. PCAP)\n");
	printf("\n");
	printf("Options:\n");
	printf("  -f \"<filter>\"          apply given packet filter on the input file\n");
	printf("  -r <string>            set ARFF @relation to given string\n");
	printf("  -H                     skip ARFF header\n");
	printf("  -d <dir>               directory to look for modules in [%s]\n", MYDIR);
	printf("  -e <modules>           comma-separated list of modules to enable\n");
	printf("  -l                     list available modules\n");
	printf("  -a                     start TCP flows with any packet\n");
	printf("  -b                     skip TCP flows with packet loss\n");
	printf("  -c                     skip TCP flows that did not close properly\n");
	printf("  -n <packets>           limit statistics to first n packets (e.g. 3)\n");
	printf("  -t <time>              limit statistics to first <time> seconds (e.g. 1.5)\n");
	printf("  --verbose,-V           be verbose (alias for --debug=5)\n");
	printf("  --debug=<num>          set debugging level\n");
	printf("  --help,-h              show this usage help screen\n");
	printf("  --version,-v           show version and copying information\n");
}

/** Prints version and copying information. */
static void version(void)
{
	printf("flowcalc %s\n", FLOWCALC_VER);
	printf("Copyright (C) 2012-2013 IITiS PAN <http://www.iitis.pl/>\n");
	printf("Copyright (C) 2015 Akamai Technologies, Inc. <http://www.akamai.com/>\n");
	printf("Licensed under GNU GPL v3\n");
	printf("Author: Paweł Foremski <pjf@foremski.pl>\n");
	printf("Part of the MuTriCs project: <http://mutrics.iitis.pl/>\n");
	printf("Partly realized under grant nr 2011/01/N/ST6/07202 of the Polish National Science Centre\n");
}

/** Parses arguments and loads modules
 * @retval 0     ok
 * @retval 1     error, main() should exit (eg. wrong arg. given)
 * @retval 2     ok, but main() should exit (eg. on --version or --help) */
static int parse_argv(struct flowcalc *fc, int argc, char *argv[])
{
	int i, c;
	char *d, *s;

	static char *short_opts = "hvVf:r:d:e:an:t:lHbc";
	static struct option long_opts[] = {
		/* name, has_arg, NULL, short_ch */
		{ "verbose",    0, NULL,  1  },
		{ "debug",      1, NULL,  2  },
		{ "help",       0, NULL,  3  },
		{ "version",    0, NULL,  4  },
		{ 0, 0, 0, 0 }
	};

	/* defaults */
	debug = 0;
	fc->dir = MYDIR;

	for (;;) {
		c = getopt_long(argc, argv, short_opts, long_opts, &i);
		if (c == -1) break; /* end of options */

		switch (c) {
			case 'V':
			case  1 : debug = 5; break;
			case  2 : debug = atoi(optarg); break;
			case 'h':
			case  3 : help(); return 2;
			case 'v':
			case  4 : version(); return 2;
			case 'f': fc->filter = mmatic_strdup(fc->mm, optarg); break;
			case 'r': fc->relation = mmatic_strdup(fc->mm, optarg); break;
			case 'd': fc->dir = mmatic_strdup(fc->mm, optarg); break;
			case 'e':
				s = mmatic_strdup(fc->mm, optarg);
				while ((d = strchr(s, ','))) {
					*d = 0;
					tlist_push(fc->modules, s);
					s = d + 1;
				}
				tlist_push(fc->modules, s);
				break;
			case 'l': fc->list = true; break;
			case 'a': fc->any = true; break;
			case 'n': fc->n = strtoul(optarg, NULL, 10); break;
			case 't': fc->t = strtod(optarg, NULL); break;
			case 'H': fc->nohead = true; break;
			case 'b': fc->noloss = true; break;
			case 'c': fc->reqclose = true; break;
			default: help(); return 1;
		}
	}

	if (fc->list) {
		tlist_flush(fc->modules);
		return 0;
	}

	if (argc - optind > 0) {
		fc->file = mmatic_strdup(fc->mm, argv[optind]);
	} else {
		help();
		return 1;
	}

	return 0;
}

static void header(struct flowcalc *fc)
{
	time_t now;
	const char *name;

	time(&now);
	printf("%%%% flowcalc run at %s", ctime(&now));

	printf("%% modules: ");
	tlist_iter_loop(fc->modules, name)
		printf("%s ", name);
	printf("\n");

	if (fc->filter)
		printf("%% filter: %s\n", fc->filter);

	if (fc->relation)
		printf("\n@relation '%s'\n\n", fc->relation);
	else
		printf("\n@relation '%s'\n\n", fc->file);

	printf("%%%% flowcalc " FLOWCALC_VER "\n");
	printf("%% fc_id:       flow id\n");
	printf("%% fc_tstamp:   timestamp of first packet in the flow\n");
	printf("%% fc_duration: flow duration\n");
	printf("%% fc_proto:    transport protocol\n");
	printf("%% fc_src_addr: IP address of connection initiator\n");
	printf("%% fc_src_port: TP port number of connection initiator\n");
	printf("%% fc_dst_addr: IP address of remote peer\n");
	printf("%% fc_dst_port: TP port number of remote peer\n");

	printf("@attribute fc_id numeric\n");
	printf("@attribute fc_tstamp numeric\n");
	printf("@attribute fc_duration numeric\n");
	printf("@attribute fc_proto {TCP,UDP}\n");
	printf("@attribute fc_src_addr string\n");
	printf("@attribute fc_src_port numeric\n");
	printf("@attribute fc_dst_addr string\n");
	printf("@attribute fc_dst_port numeric\n");
	printf("\n");
}

static void flow_start(struct lfc *lfc, void *pdata, struct lfc_flow *lf, void *data)
{
	char src[50], dst[50];

	printf("%u", lf->id);
	printf(",%.6f", lf->ts_first);
	printf(",%.6f", lf->ts_last - lf->ts_first);

	if (lf->proto == IPPROTO_UDP)
		printf(",UDP");
	else
		printf(",TCP");

	if (lf->is_ip6) {
		inet_ntop(AF_INET6, &(lf->src.addr.ip6), src, sizeof src);
		inet_ntop(AF_INET6, &(lf->dst.addr.ip6), dst, sizeof dst);
	} else {
		inet_ntop(AF_INET, &(lf->src.addr.ip4), src, sizeof src);
		inet_ntop(AF_INET, &(lf->dst.addr.ip4), dst, sizeof dst);
	}

	printf(",%s,%d,%s,%d", src, lf->src.port, dst, lf->dst.port);
}

static void flow_end(struct lfc *lfc, void *pdata, struct lfc_flow *lf, void *data)
{
	printf("\n");
}

int main(int argc, char *argv[])
{
	mmatic *mm;
	struct flowcalc *fc;
	void *h;
	struct module *mod;
	char *name, *s;
	tlist *ls;
	void *pdata;

	/*
	 * initialization
	 */
	mm = mmatic_create();
	fc = mmatic_zalloc(mm, sizeof *fc);
	fc->mm = mm;
	fc->modules = tlist_create(NULL, mm);

	/* read options */
	if (parse_argv(fc, argc, argv))
		return 1;

	/* enable all modules found in given directory */
	if (tlist_count(fc->modules) == 0) {
		ls = pjf_ls(fc->dir, mm);
		tlist_iter_loop(ls, name) {
			s = strrchr(name, '.');
			if (s && streq(s, ".so")) {
				*s = 0;
				tlist_push(fc->modules, name);
			}
		}
	}

	if (fc->list) {
		printf("flowcalc modules found in %s:\n", fc->dir);
		tlist_iter_loop(fc->modules, name) {
			printf("  %s\n", name);
		}
		return 0;
	}

	fc->lfc = lfc_init();
	lfc_register(fc->lfc, "flow_start", 0, NULL, flow_start, NULL);

	if (fc->any)      lfc_enable(fc->lfc, LFC_OPT_TCP_ANYSTART, NULL);
	if (fc->n > 0)    lfc_enable(fc->lfc, LFC_OPT_PACKET_LIMIT, &(fc->n));
	if (fc->t > 0.0)  lfc_enable(fc->lfc, LFC_OPT_TIME_LIMIT, &(fc->t));
	if (fc->noloss)   lfc_enable(fc->lfc, LFC_OPT_TCP_NOLOSS, NULL);
	if (fc->reqclose) lfc_enable(fc->lfc, LFC_OPT_TCP_REQCLOSE, NULL);

	/*
	 * load modules and draw ARFF header
	 */
	if (!fc->nohead)
		header(fc);

	tlist_iter_loop(fc->modules, name) {
		if (streq(name, "none"))
			break;

		h = dlopen(mmatic_sprintf(mm, "%s/%s.so", fc->dir, name), RTLD_LOCAL | RTLD_LAZY);
		if (!h)
			die("Opening module '%s' failed: %s\n", name, dlerror());

		mod = dlsym(h, "module");
		if (!mod)
			die("Opening module '%s' failed: no 'module' variable found inside\n", name);

		pdata = NULL;
		if (mod->init) {
			if (!mod->init(fc->lfc, &pdata, fc))
				die("Opening module '%s' failed: the init() function returned false\n", name);
		}

		if (!fc->nohead && mod->header) {
			mod->header(fc->lfc, pdata, fc);
			printf("\n");
		}

		lfc_register(fc->lfc, name, mod->size, mod->pkt, mod->flow, pdata);
	}

	lfc_register(fc->lfc, "flow_end", 0, NULL, flow_end, NULL);

	/*
	 * run it!
	 */
	if (!fc->nohead)
		printf("@data\n");

	if (!lfc_run(fc->lfc, fc->file, fc->filter))
		die("Reading file '%s' failed\n", fc->file);

	lfc_deinit(fc->lfc);
	mmatic_destroy(mm);

	return 0;
}
