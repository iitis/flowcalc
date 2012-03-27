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

struct module {
	/** Module name */
	const char *name;

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

#endif
