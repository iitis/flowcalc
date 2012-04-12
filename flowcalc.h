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
	int size;                      /**> Flow data size (bytes) */
	pkt_cb pkt;                    /**> Per-packet callback */
	flow_cb flow;                  /**> Flow-timeout callback */

	/**> Optional initialization function
	 * @param pdata    space for storing pdata address (optional)
	 * @retval false   initialization failed
	 */
	bool (*init)(struct lfc *lfc, void **pdata);
};

struct flowcalc {
	mmatic *mm;           /**> memory */
	struct lfc *lfc;      /**> libflowcalc handle */

	const char *file;     /**> trace file */
	const char *filter;   /**> optional filter */
	const char *relation; /**> ARFF @relation */
	tlist *modules;       /**> list of char*: modules */
	const char *dir;      /**> module directory */
	bool any;             /**> enable LFM_CONFIG_TCP_ANYSTART? */
};

#endif
