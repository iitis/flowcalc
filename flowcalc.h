/*
 * flowcalc: convert PCAP traffic to WEKA files
 * Copyright (C) 2012-2015 IITiS PAN Gliwice <http://www.iitis.pl/>
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

#ifndef _FLOWCALC_H_
#define _FLOWCALC_H_

#include <libflowcalc.h>

#define FLOWCALC_VER "0.2"

#ifndef MYDIR
#define MYDIR "."
#endif

struct flowcalc {
	mmatic *mm;           /**> memory */
	struct lfc *lfc;      /**> libflowcalc handle */

	const char *file;     /**> trace file */
	const char *filter;   /**> optional filter */
	const char *relation; /**> ARFF @relation */
	bool nohead;          /**> no ARFF header? */
	tlist *modules;       /**> list of char*: modules */
	bool list;            /**> list modules and quit */
	const char *dir;      /**> module directory */
	bool any;             /**> enable LFM_CONFIG_TCP_ANYSTART? */
	bool noloss;          /**> skip TCP flows with packet loss */
	bool reqclose;        /**> skip TCP flows that did not close properly */

	unsigned long n;      /**> packet limit */
	double t;             /**> time limit */
};

struct module {
	int size;                      /**> Flow data size (bytes) */
	pkt_cb pkt;                    /**> Per-packet callback */
	flow_cb flow;                  /**> Flow-timeout callback */

	/**> Optional initialization function
	 * @param lfc      access to libflowcalc configuration, etc.
	 * @param plugin   space for storing plugin data (optional)
	 * @param fc       access to flowcalc configuration, etc.
	 * @retval false   initialization failed
	 */
	bool (*init)(struct lfc *lfc, void **plugin, struct flowcalc *fc);

	/**> Print ARFF header
	 * @param lfc      libflowcalc configuration, etc.
	 * @param plugin   plugin data
	 * @param fc       flowcalc configuration, etc.
	 */
	void (*header)(struct lfc *lfc, void *plugin, struct flowcalc *fc);
};

#endif
