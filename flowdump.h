/*
 * flowdump
 *
 * Author: Paweł Foremski
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#ifndef _FLOWDUMP_H_
#define _FLOWDUMP_H_

#include <libflowcalc.h>

#define FLOWDUMP_VER "0.1"

struct flow {
	libtrace_out_t *out;    /**> output file handle */
	bool ignore;            /**> if true, skip this flow */
};

struct flowdump {
	mmatic *mm;             /**> memory */
	struct lfc *lfc;        /**> libflowcalc handle */

	const char *arff_file;  /**> ARFF file */
	FILE *afh;              /**> arff_file fopen() */
	uint16_t colnum;        /**> column number */
	thash *cache;           /**> cache: flow id -> name */

	const char *pcap_file;  /**> trace file */
	const char *filter;     /**> optional filter */

	const char *dir;        /**> output directory */
	thash *out_files;       /**> name -> libtrace_t* */
};

#endif
