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

#ifndef MYDIR
#define MYDIR "."
#endif

struct flowcalc {
	mmatic *mm;           /**> memory */
	struct lfc *lfc;      /**> libflowcalc handle */

	const char *file;     /**> trace file */
	const char *filter;   /**> optional filter */
	const char *relation; /**> ARFF @relation */
	tlist *modules;       /**> list of char*: modules */
	const char *dir;      /**> module directory */
	bool any;             /**> enable LFM_CONFIG_TCP_ANYSTART? */

	unsigned long n;      /**> packet limit */
	double t;             /**> time limit */
};

struct module {
	int size;                      /**> Flow data size (bytes) */
	pkt_cb pkt;                    /**> Per-packet callback */
	flow_cb flow;                  /**> Flow-timeout callback */

	/**> Optional initialization function
	 * @param lfc      access to libflowcalc configuration, etc.
	 * @param pdata    space for storing plugin data address (optional)
	 * @param fc       access to flowcalc configuration, etc.
	 * @retval false   initialization failed
	 */
	bool (*init)(struct lfc *lfc, void **pdata, struct flowcalc *fc);
};

#endif
