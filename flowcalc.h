/*
 * flowcalc
 *
 * Author: Paweł Foremski
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#ifndef _FLOWCALC_H_
#define _FLOWCALC_H_

#include <libflowcalc.h>

#define FLOWCALC_VER "0.1"

struct module {
	/** Flow data size (bytes) */
	int size;

	/** Initialization function
	 * @retval false  failed
	 */
	bool (*init)(struct lfc *lfc);

	/** Per-packet callback */
	pkt_cb pkt;

	/** Flow-timeout callback */
	flow_cb flow;
};

struct flowcalc {
	mmatic *mm;           /**> memory */
	struct lfc *lfc;      /**> libflowcalc handle */

	tlist *files;         /**> list of char*: files to process */
	const char *filter;   /**> optional filter */
	const char *relation; /**> ARFF @relation */
	tlist *modules;       /**> list of char*: modules */
	const char *dir;      /**> module directory */
};

#endif
