/*
 * flowcalc
 * Copyright (c) 2012-2013 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 *
 * Licensed under GNU GPL v. 3
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <time.h>
#include <getopt.h>

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
	printf("  -d <dir>               directory to look for modules in\n");
	printf("  -e <modules>           comma-separated list of modules to enable\n");
	printf("  -a                     start TCP flows with any packet\n");
	printf("  --verbose,-V           be verbose (alias for --debug=5)\n");
	printf("  --debug=<num>          set debugging level\n");
	printf("  --help,-h              show this usage help screen\n");
	printf("  --version,-v           show version and copying information\n");
}

/** Prints version and copying information. */
static void version(void)
{
	printf("flowcalc %s\n", FLOWCALC_VER);
	printf("Author: Paweł Foremski <pjf@iitis.pl>\n");
	printf("Copyright (C) 2012-2013 IITiS PAN\n");
	printf("Licensed under GNU GPL v3\n");
	printf("Part of the MuTriCs project: <http://mutrics.iitis.pl/>\n");
	printf("Realized under grant nr 2011/01/N/ST6/07202 of the Polish National Science Centre\n");
}

/** Parses arguments and loads modules
 * @retval 0     ok
 * @retval 1     error, main() should exit (eg. wrong arg. given)
 * @retval 2     ok, but main() should exit (eg. on --version or --help) */
static int parse_argv(struct flowcalc *fc, int argc, char *argv[])
{
	int i, c;
	char *d, *s;

	static char *short_opts = "hvVf:r:d:e:a";
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
			case 'a': fc->any = true; break;
			default: help(); return 1;
		}
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
	printf("%u", lf->id);

	printf(",%.6f", lf->ts_first);
	printf(",%.6f", lf->ts_last - lf->ts_first);

	if (lf->proto == IPPROTO_UDP)
		printf(",UDP");
	else
		printf(",TCP");

	printf(",%s,%d", inet_ntoa(lf->src.addr.ip4), lf->src.port);
	printf(",%s,%d", inet_ntoa(lf->dst.addr.ip4), lf->dst.port);

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

	fc->lfc = lfc_init();
	lfc_register(fc->lfc, "flow_start", 0, NULL, flow_start, NULL);

	if (fc->any)
		lfc_enable(fc->lfc, LFC_OPT_TCP_ANYSTART);

	/*
	 * load modules and draw ARFF header
	 */
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

		if (mod->init) {
			pdata = NULL;
			if (!mod->init(fc->lfc, &pdata))
				die("Opening module '%s' failed: the init() function returned false\n", name);
			else
				printf("\n");
		}

		lfc_register(fc->lfc, name, mod->size, mod->pkt, mod->flow, pdata);
	}

	lfc_register(fc->lfc, "flow_end", 0, NULL, flow_end, NULL);

	/*
	 * run it!
	 */
	printf("@data\n");

	if (!lfc_run(fc->lfc, fc->file, fc->filter))
		die("Reading file '%s' failed\n", fc->file);

	lfc_deinit(fc->lfc);
	mmatic_destroy(mm);

	return 0;
}
