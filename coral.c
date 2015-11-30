/*
 * coral - CAIDA CoralReef port number traffic classifier
 *
 * Author: Paweł Foremski
 * Copyright (c) 2013 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <libpjf/lib.h>
#include "flowcalc.h"

struct coral {
	thash *ports;             /**> thash: (int) port number -> tlist of struct port */
	struct lfc *lfc;          /**> access to libflowcalc */
	struct flowcalc *fc;      /**> access to flowcalc */
};

/* Represents a single port -> protocol definition */
struct port {
	int prio;                 /**> rule priority: lower is better */
	char *name;               /**> protocol name */
	char *group;              /**> protocol group */
	bool tcp;                 /**> match TCP flows? */
	bool udp;                 /**> match UDP flows? */
	thash *portset;           /**> remote ports: null OR thash: (int) number->true */
};

/*****************************/

/** Parse a range of ports, e.g. 80,8080,6000-6100 */
thash *portset_parse(struct coral *coral, char descr[128])
{
	mmatic *mm = coral->lfc->mm;
	thash *set;
	char *str, *tok, *ptr;
	int i, p1, p2;

	set = thash_create_intkey(NULL, mm);

	/* parse token-by-token (separated with commas) */
	for (str = descr;; str = NULL) {
		tok = strtok(str, ",");
		if (!tok) break;

		/* is it a list? */
		ptr = strchr(tok, '-');
		if (!ptr) {
			p1 = atoi(tok);
			thash_uint_set_true(set, p1);
		} else {
			*ptr++ = '\0';
			p1 = atoi(tok);
			p2 = atoi(ptr);
			for (i = p1; i <= p2; i++)
				thash_uint_set_true(set, i);
		}
	}

	return set;
}

/** Append given port definition to the database */
void ports_append(struct coral *coral, int portnum, struct port *portdef)
{
	mmatic *mm = coral->lfc->mm;
	tlist *list;
	struct port *port;

	list = thash_uint_get(coral->ports, portnum);
	if (!list) {
		list = tlist_create(NULL, mm);
		thash_uint_set(coral->ports, portnum, list);
	}

	/* try to respect priorities */
	tlist_reset(list);
	while (((port) = tlist_iter(list))) {
		if (portdef->prio < port->prio) {
			tlist_insertbefore(list, portdef);
			return;
		}
	}

	/* if that failed, add at the end */
	tlist_push(list, portdef);
}

/** Match protocol to given ports and protocol */
struct port *port_match(struct coral *coral, uint16_t proto, unsigned long sport, unsigned long dport)
{
	tlist *list;
	struct port *port;

	/* query the database for destination port number */
	list = thash_uint_get(coral->ports, dport);
	if (!list)
		return NULL;

	/* go through the list of possible matchings */
	tlist_reset(list);
	while (((port) = tlist_iter(list))) {
		/* check IP protocol */
		switch (proto) {
			case IPPROTO_TCP:
				if (!port->tcp) continue;
				break;
			case IPPROTO_UDP:
				if (!port->udp) continue;
				break;
		}

		/* no port list = it matches */
		if (!port->portset)
			return port;
	
		/* check port list */
		if (thash_uint_get(port->portset, sport))
			return port;
	}

	/* nothing matched */
	return NULL;
}


/** Parse port definition and call ports_append to add the data to global database */
void port_parse(struct coral *coral,
	char name[128], char group[128],
	char sports_str[128], char dports_str[128],
	char proto_str[128], char prio_str[128])
{
	mmatic *mm = coral->lfc->mm;
	struct port *p;
	char *tmp;
	thash *sports;
	unsigned long pnum;
	bool tcp = false, udp = false;

	/* filter by IP protocol */
	if (streq(proto_str, "6")) tcp = true;
	else if (streq(proto_str, "17")) udp = true;
	else if (streq(proto_str, "6,17")) tcp = udp = true;
	else return;

	/* set default values */
	if (streq(group, "")) group = "?";
	if (streq(prio_str, "")) prio_str = "50";

	if (streq(sports_str, "*")) {
		if (streq(dports_str, "*")) return; /* should not happen */
		tmp = dports_str;
		dports_str = sports_str;
		sports_str = tmp;
	}

	/*
	 * create new port
	 */
	p = mmatic_zalloc(mm, sizeof *p);

	p->name = mmatic_strdup(mm, name);
	p->group = mmatic_strdup(mm, group);
	p->tcp = tcp;
	p->udp = udp;
	p->prio = atoi(prio_str);

	if (streq(dports_str, "*"))
		p->portset = NULL;
	else
		p->portset = portset_parse(coral, dports_str);

	/* add to the list */
	sports = portset_parse(coral, sports_str);
	thash_reset(sports);
	while (thash_uint_iter(sports, &pnum))
		ports_append(coral, pnum, p);

	thash_free(sports);
}

/** Print the whole ports database */
void ports_print(struct coral *coral)
{
	unsigned long pnum;
	tlist *list;
	struct port *port;

	thash_reset(coral->ports);
	while (((list) = thash_uint_iter(coral->ports, &pnum))) {
		printf("%4lu: ", pnum);

		tlist_reset(list);
		while (((port) = tlist_iter(list)))
			printf("%s (%d) ", port->name, port->prio);

		printf("\n");
	}
}

/*****************************/

bool init(struct lfc *lfc, void **pdata, struct flowcalc *fc)
{
	struct coral *coral;
	FILE *fp;
	char buf[1024], *key, *val, *ptr;
	char dbpath[512];
	int i;

	char name[128] = {0}, group[128] = {0};
	char sports[128] = {0}, dports[128] = {0};
	char proto[128] = {0}, prio[128] = {0};

	/* read the CoralReef database */
	coral = mmatic_zalloc(lfc->mm, sizeof *coral);
	coral->ports = thash_create_intkey(NULL, lfc->mm);
	coral->lfc = lfc;
	coral->fc = fc;

	/* open the file */
	strncpy(dbpath, fc->dir, sizeof dbpath);
	strncat(dbpath, "/coral/Application_ports_Master.txt", sizeof dbpath);
	fp = fopen(dbpath, "r");
	if (!fp) {
		dbg(0, "could not open CoralReef port database from %s: %m\n", dbpath);
		return false;
	}

	/* parse line-by-line */
	while (fgets(buf, sizeof buf, fp)) {
		switch (buf[0]) {
			case '#': case '\n': case 0: continue;
		}

		/* split by colon */
		ptr = strchr(buf, ':');
		if (!ptr) continue;

		*ptr++ = '\0';
		while (*ptr && isspace(*ptr)) ptr++;

		/* read it */
		key = buf;
		val = ptr;

		/* trim val */
		for (i = strlen(val) - 1; i >= 0 && isspace(val[i]); i--)
			val[i] = '\0';

		/*
		 * use it!
		 */
		/* 'description:' starts new definition */
		if (streq(key, "description")) {
			if (name[0])
				port_parse(coral, name, group, sports, dports, proto, prio);

			bzero(name, sizeof name);
			bzero(group, sizeof group);
			bzero(sports, sizeof sports);
			bzero(dports, sizeof dports);
			bzero(proto, sizeof proto);
			bzero(prio, sizeof prio);
		}

		else if (streq(key, "name")) {
			for (i = 0; val[i]; i++)
				if (!isalnum(val[i])) val[i] = '_';
			strncpy(name, val, sizeof name);
		} else if (streq(key, "group")) {
			strncpy(group, val, sizeof group);
		} else if (streq(key, "sport")) {
			strncpy(sports, val, sizeof sports);
		} else if (streq(key, "dport")) {
			strncpy(dports, val, sizeof dports);
		} else if (streq(key, "protocol")) {
			strncpy(proto, val, sizeof proto);
		} else if (streq(key, "priority")) {
			strncpy(prio, val, sizeof prio);
		}
	}
	fclose(fp);

	//ports_print(coral);

	*pdata = coral;
	return true;
}

void header()
{
	printf("%%%% coral 0.1\n");
	printf("%% crl_group: protocol group\n");
	printf("%% crl_name: protocol name\n");
	printf("@attribute crl_group string\n");
	printf("@attribute crl_name string\n");
}

void flow(struct lfc *lfc, void *pdata, struct lfc_flow *lf, void *data)
{
	struct coral *coral = pdata;
	unsigned long sport, dport;
	struct port *port;

	sport = lf->src.port;
	dport = lf->dst.port;

	/* 1. try normal direction */
	port = port_match(coral, lf->proto, sport, dport);

	/* 2. try opposite direction? */
	if (!port)
		port = port_match(coral, lf->proto, dport, sport);

	/* 3. print the result */
	if (port)
		printf(",%s,%s", port->group, port->name);
	else
		printf(",?crl_group,?crl_name");
}

struct module module = {
	.size = 0,
	.init = init,
	.header = header,
	.pkt  = NULL,
	.flow = flow
};
