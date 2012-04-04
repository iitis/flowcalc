/*
 * flowdump
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 *
 * Licensed under GNU GPL v. 3
 */

#include <getopt.h>
#include <ctype.h>
#include <string.h>

#include <libpjf/main.h>
#include <libflowcalc.h>

#include "flowdump.h"

/** Prints usage help screen */
static void help(void)
{
	printf("Usage: flowdump [OPTIONS] <TRACE FILE> <ARFF FILE>\n");
	printf("\n");
	printf("  Rewrites one IP trace file into many files basing on e.g. the L7 protocol\n");
	printf("\n");
	printf("Options:\n");
	printf("  -f \"<filter>\"          apply given packet filter on the input trace file\n");
	printf("  -d <dir>               output directory\n");
	printf("  -c <num>               use column <num> as the output file name\n");
	printf("  --verbose,-V           be verbose (alias for --debug=5)\n");
	printf("  --debug=<num>          set debugging level\n");
	printf("  --help,-h              show this usage help screen\n");
	printf("  --version,-v           show version and copying information\n");
}

/** Prints version and copying information. */
static void version(void)
{
	printf("flowdump %s\n", FLOWDUMP_VER);
	printf("Author: Paweł Foremski <pjf@iitis.pl>\n");
	printf("Copyright (C) 2012 IITiS PAN\n");
	printf("Licensed under GNU GPL v3\n");
	printf("Part of the MuTriCs project: <http://mutrics.iitis.pl/>\n");
	printf("Realized under grant nr 2011/01/N/ST6/07202 of the Polish National Science Centre\n");
}

/** Parses arguments and loads modules
 * @retval 0     ok
 * @retval 1     error, main() should exit (eg. wrong arg. given)
 * @retval 2     ok, but main() should exit (eg. on --version or --help) */
static int parse_argv(struct flowdump *fd, int argc, char *argv[])
{
	int i, c;

	static char *short_opts = "hvVf:d:c:";
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
	fd->dir = ".";

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
			case 'f': fd->filter = mmatic_strdup(fd->mm, optarg); break;
			case 'd': fd->dir = mmatic_strdup(fd->mm, optarg); break;
			case 'c': fd->colnum = atoi(optarg); break;
			default: help(); return 1;
		}
	}

	if (argc - optind > 1) {
		fd->pcap_file = mmatic_strdup(fd->mm, argv[optind]);
		fd->arff_file = mmatic_strdup(fd->mm, argv[optind+1]);
	} else {
		help();
		return 1;
	}

	return 0;
}

/*******************************/

static void cache_update(struct flowdump *fd)
{
	char buf[BUFSIZ], *ptr, *cm;
	int i;
	unsigned int id;

	if (!fd->afh)
		return;

	if (thash_count(fd->cache) > 50000000)
		return;

	while (thash_count(fd->cache) < 10000000 && fgets(buf, sizeof buf, fd->afh)) {
		if (!isdigit(buf[0]))
			continue;

		ptr = buf;
		cm = strchr(ptr, ',');
		if (!cm)
			continue;
		else
			*cm = '\0';

		/* get flow id */
		id = atoi(ptr);

		/* get flow target */
		for (i = 1; i < fd->colnum; i++) {
			ptr = cm + 1;
			cm = strchr(ptr, ',');
			if (!cm) {
				cm = strchr(ptr, '\n');
				break;
			}
		}

		if (cm)
			*cm = '\0';

		for (i = 0; ptr[i]; i++) {
			if (!isalnum(ptr[i]))
				ptr[i] = '_';
		}

		thash_uint_set(fd->cache, id, mmatic_strdup(fd->mm, ptr));
	}

	if (feof(fd->afh)) {
		fclose(fd->afh);
		fd->afh = NULL;
	}
}

/*******************************/

static void pkt(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	struct flowdump *fd = pdata;
	struct flow *f = data;
	char *name, *uri;
	libtrace_out_t *out;

	if (f->ignore)
		return;

	if (is_new) {
		/* get output file name */
		name = thash_uint_get(fd->cache, lf->id);
		if (!name) {
			cache_update(fd);
			name = thash_uint_get(fd->cache, lf->id);
			if (!name) {
				f->ignore = true;
				return;
			}
		}

		/* get libtrace output file */
		out = thash_get(fd->out_files, name);
		if (!out) {
			uri = mmatic_sprintf(fd->mm, "pcap:%s/%s.pcap", fd->dir, name);

			out = trace_create_output(uri);
			if (!out)
				die("trace_create_output(%s) failed\n", uri);

			if (trace_is_err_output(out)) {
				trace_perror_output(out, "Opening output trace file");
				die("trace_create_output(%s) failed\n", uri);
			}

			if (trace_start_output(out) == -1) {
				trace_perror_output(out, "Starting output trace");
				die("trace_start_output(%s) failed\n", uri);
			}

			thash_set(fd->out_files, name, out);
		}

		f->out = out;

		/* remove id from cache */
		thash_uint_set(fd->cache, lf->id, NULL);
	}

	trace_write_packet(f->out, pkt);
	if (trace_is_err_output(f->out)) {
		trace_perror_output(f->out, "Writing packet to output trace file");
		die("trace_write_packet() failed\n");
	}
}

/*******************************/

int main(int argc, char *argv[])
{
	mmatic *mm;
	struct flowdump *fd;

	/*
	 * initialization
	 */
	mm = mmatic_create();
	fd = mmatic_zalloc(mm, sizeof *fd);
	fd->mm = mm;
	fd->cache = thash_create_intkey(mmatic_free, mm);
	fd->out_files = thash_create_strkey(trace_destroy_output, mm);

	/* read options */
	if (parse_argv(fd, argc, argv))
		return 1;

	/* file-system init */
	{
		if (streq(fd->arff_file, "-")) {
			fd->afh = stdin;
		} else {
			fd->afh = fopen(fd->arff_file, "r");
			if (!fd->afh)
				die("Reading input ARFF file '%s' failed: %s\n", fd->arff_file, strerror(errno));
		}

		if (pjf_mkdir(fd->dir) != 0)
			die("Creating output directory '%s' failed\n", fd->dir);
	}

	fd->lfc = lfc_init();
	lfc_register(fd->lfc, "flowdump", sizeof(struct flow), pkt, NULL, fd);

	if (!lfc_run(fd->lfc, fd->pcap_file, fd->filter))
		die("Reading file '%s' failed\n", fd->pcap_file);

	lfc_deinit(fd->lfc);
	thash_free(fd->out_files);
	mmatic_destroy(mm);

	return 0;
}
