/* This piece of code is a wrapper around libiptc from netfilter/iptables
 * for managing rules and chains.
 */

/*
 * Author: Derrik Pates <dpates@dsdk12.net>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <libiptc/libiptc.h>
#include <errno.h>
#include "packer.h"
#include "unpacker.h"
#include "maskgen.h"
#include "module_iface.h"

typedef iptc_handle_t* IPTables__IPv4__Table;

MODULE = IPTables::IPv4		PACKAGE = IPTables::IPv4

IPTables::IPv4::Table
init(tablename)
	char *	tablename
	PREINIT:
	iptc_handle_t	handle;
	CODE:
		
		handle = iptc_init(tablename);
		if(handle == NULL) {
			RETVAL = NULL;
			SET_ERRNUM(errno);
			SET_ERRSTR("%s", iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}
		else {
			RETVAL = malloc(sizeof(iptc_handle_t));
			*RETVAL = handle;
		}
	OUTPUT:
	RETVAL
		
MODULE = IPTables::IPv4		PACKAGE = IPTables::IPv4::Table

int
is_chain(self, chain)
	IPTables::IPv4::Table	self
	char *			chain
	PREINIT:
	ipt_chainlabel	label;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		RETVAL = iptc_is_chain(label, *self);
	OUTPUT:
	RETVAL

void
list_chains(self)
	IPTables::IPv4::Table	self
	PREINIT:
	char *			chain;
	SV *			sv;
	PPCODE:
		sv = ST(0);
		chain = (char *)iptc_first_chain(self);
		while(chain) {
			XPUSHs(sv_2mortal(newSVpv(chain, 0)));
			chain = (char *)iptc_next_chain(self);
		}

void
list_rules(self, chain)
	IPTables::IPv4::Table	self
	const char *			chain
	PREINIT:
	ipt_chainlabel			label;
	SV *					sv;
	PPCODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		sv = ST(0);
		if(iptc_is_chain(label, *self)) {
			struct ipt_entry *entry =
			    (struct ipt_entry *)iptc_first_rule(label, self);
			while(entry) {
				XPUSHs(sv_2mortal(newRV_inc((SV*)ipt_do_unpack(entry, self))));
				entry = (struct ipt_entry *)iptc_next_rule(entry, self);
			}
		}

int
builtin(self, chain)
	IPTables::IPv4::Table	self
	char *					chain
	PREINIT:
	ipt_chainlabel			label;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		RETVAL = iptc_builtin(label, *self);
	OUTPUT:
	RETVAL

void
get_policy(self, chain)
	IPTables::IPv4::Table	self
	const char *			chain
	PREINIT:
	ipt_chainlabel			label;
	struct ipt_counters		counter;
	SV *					sv;
	char *					target;
	char *					temp;
	PPCODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		sv = ST(0);
		if((target = (char *)iptc_get_policy(label, &counter, self))) {
			XPUSHs(sv_2mortal(newSVpv(target, 0)));
			asprintf(&temp, "%llu", counter.pcnt);
			XPUSHs(sv_2mortal(newSVpv(temp, 0)));
			free(temp);
			asprintf(&temp, "%llu", counter.bcnt);
			XPUSHs(sv_2mortal(newSVpv(temp, 0)));
			free(temp);
		}
		else {
			SET_ERRNUM(errno);
			SET_ERRSTR(iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}

int
insert_entry(self, chain, entry, rulenum)
	IPTables::IPv4::Table	self
	const char *			chain
	SV *					entry
	unsigned int			rulenum
	PREINIT:
	ipt_chainlabel			label;
	struct ipt_entry *		ent;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		if(ipt_do_pack((HV *)SvRV(entry), &ent, self)) {
			RETVAL = iptc_insert_entry(label, ent, rulenum, self);
			if(!RETVAL) {
				SET_ERRNUM(errno);
				SET_ERRSTR("%s", iptc_strerror(errno));
				SvIOK_on(ERROR_SV);
			}
		}
		else
			RETVAL = FALSE;
		free(ent);
	OUTPUT:
	RETVAL

int
replace_entry(self, chain, entry, rulenum)
	IPTables::IPv4::Table	self
	const char *			chain
	SV *					entry
	unsigned int			rulenum
	PREINIT:
	ipt_chainlabel			label;
	struct ipt_entry *		ent;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		if(ipt_do_pack((HV *)SvRV(entry), &ent, self)) {
			RETVAL = iptc_replace_entry(label, ent, rulenum, self);
			if(!RETVAL) {
				SET_ERRNUM(errno);
				SET_ERRSTR("%s", iptc_strerror(errno));
				SvIOK_on(ERROR_SV);
			}
		}
		else
			RETVAL = FALSE;
		free(ent);
	OUTPUT:
	RETVAL

int
append_entry(self, chain, entry)
	IPTables::IPv4::Table	self
	const char *			chain
	SV *					entry
	PREINIT:
	ipt_chainlabel			label;
	struct ipt_entry *		ent;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		if(ipt_do_pack((HV *)SvRV(entry), &ent, self)) {
			RETVAL = iptc_append_entry(label, ent, self);
			if(!RETVAL) {
				SET_ERRNUM(errno);
				SET_ERRSTR(iptc_strerror(errno));
				SvIOK_on(ERROR_SV);
			}
		}	
		else
			RETVAL = FALSE;
		free(ent);
	OUTPUT:
	RETVAL

int
delete_entry(self, chain, origfw)
	IPTables::IPv4::Table	self
	const char *			chain
	SV *					origfw
	PREINIT:
	unsigned char *			matchmask = NULL;
	ipt_chainlabel			label;
	struct ipt_entry *		ent;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		if(ipt_do_pack((HV *)SvRV(origfw), &ent, self)) {
			if((matchmask = ipt_gen_delmask(ent))) {
				RETVAL = iptc_delete_entry(label, ent, matchmask, self);
				if(!RETVAL) {
					SET_ERRNUM(errno);
					SET_ERRSTR(iptc_strerror(errno));
					SvIOK_on(ERROR_SV);
				}
			}
			else {
				SET_ERRSTR("Unable to generate matchmask");
				RETVAL = FALSE;
			}
		}
		else
			RETVAL = FALSE;
		free(ent);
		free(matchmask);
	OUTPUT:
	RETVAL

int
delete_num_entry(self, chain, rulenum)
	IPTables::IPv4::Table	self
	const char *			chain
	unsigned int			rulenum
	PREINIT:
	ipt_chainlabel			label;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		RETVAL = iptc_delete_num_entry(label, rulenum, self);
		if(!RETVAL) {
			SET_ERRNUM(errno);
			SET_ERRSTR("%s", iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}
	OUTPUT:
	RETVAL

int
flush_entries(self, chain)
	IPTables::IPv4::Table	self
	char *					chain
	PREINIT:
	ipt_chainlabel			label;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		RETVAL = iptc_flush_entries(label, self);
		if(!RETVAL) {
			SET_ERRNUM(errno);
			SET_ERRSTR("%s", iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}
	OUTPUT:
	RETVAL

int
zero_entries(self, chain)
	IPTables::IPv4::Table	self
	const char *			chain
	PREINIT:
	ipt_chainlabel			label;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		RETVAL = iptc_zero_entries(label, self);
		if(!RETVAL) {
			SET_ERRNUM(errno);
			SET_ERRSTR(iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}
	OUTPUT:
	RETVAL

int
create_chain(self, chain)
	IPTables::IPv4::Table	self
	const char *			chain
	PREINIT:
	ipt_chainlabel			label;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		RETVAL = iptc_create_chain(label, self);
		if(!RETVAL) {
			SET_ERRNUM(errno);
			SET_ERRSTR(iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}
	OUTPUT:
	RETVAL

int
delete_chain(self, chain)
	IPTables::IPv4::Table	self
	const char *			chain
	PREINIT:
	ipt_chainlabel			label;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		RETVAL = iptc_delete_chain(label, self);
		if(!RETVAL) {
			SET_ERRNUM(errno);
			SET_ERRSTR("%s", iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}
	OUTPUT:
	RETVAL

int
rename_chain(self, oldname, newname)
	IPTables::IPv4::Table	self
	const char *			oldname
	const char *			newname
	PREINIT:
	ipt_chainlabel			olabel, nlabel;
	CODE:
		memset(olabel, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(olabel, oldname, IPT_FUNCTION_MAXNAMELEN);
		memset(nlabel, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(nlabel, newname, IPT_FUNCTION_MAXNAMELEN);
		RETVAL = iptc_rename_chain(olabel, nlabel, self);
		if(!RETVAL) {
			SET_ERRNUM(errno);
			SET_ERRSTR("%s", iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}
	OUTPUT:
	RETVAL

int
set_policy(self, chain, policy, count = NULL)
	IPTables::IPv4::Table	self
	const char *			chain
	const char *			policy
	SV *					count
	PREINIT:
	ipt_chainlabel			clabel, plabel;
	struct ipt_counters *	counters = NULL;
	HV *					hash;
	SV *					sv;
	char *					h_key;
	int						h_keylen;
	CODE:
		RETVAL = TRUE;
		if(count) {
			if((SvTYPE(count) == SVt_RV) && (hash = (HV *)SvRV(count)) &&
							(SvTYPE(hash) == SVt_PVHV)) {
				hv_iterinit(hash);
				counters = malloc(sizeof(struct ipt_counters));
				while((sv = hv_iternextsv(hash, &h_key, (I32 *)&h_keylen))) {
					if(!strcmp(h_key, "pcnt")) {
						if(SvTYPE(sv) == SVt_IV)
							counters->pcnt = SvUV(sv);
						else if(SvPOK(sv))
							sscanf(SvPV_nolen(sv), "%Lu", &counters->pcnt);
						else
							croak("pcnt is not an integer");
					}
					else if(!strcmp(h_key, "bcnt")) {
						if(SvTYPE(sv) == SVt_IV)
							counters->bcnt = SvUV(sv);
						else if(SvPOK(sv))
							sscanf(SvPV_nolen(sv), "%Lu", &counters->bcnt);
						else
							croak("bcnt is not an integer");
					}
					else
						croak("invalid key in 'count' hash");
				}
			}
			else
				croak("count is not a hashref");
		}
		if(RETVAL) {
			memset(clabel, 0, IPT_FUNCTION_MAXNAMELEN + 1);
			strncpy(clabel, chain, IPT_FUNCTION_MAXNAMELEN);
			memset(plabel, 0, IPT_FUNCTION_MAXNAMELEN + 1);
			strncpy(plabel, policy, IPT_FUNCTION_MAXNAMELEN);
			RETVAL = iptc_set_policy(clabel, plabel, counters, self);
			if(!RETVAL) {
				SET_ERRNUM(errno);
				SET_ERRSTR("%s", iptc_strerror(errno));
				SvIOK_on(ERROR_SV);
			}
		}
		if(counters)
			free(counters);
	OUTPUT:
	RETVAL

int
get_references(self, chain)
	IPTables::IPv4::Table	self
	const char *			chain
	PREINIT:
	ipt_chainlabel			label;
	CODE:
		memset(label, 0, IPT_FUNCTION_MAXNAMELEN + 1);
		strncpy(label, chain, IPT_FUNCTION_MAXNAMELEN);
		if(!iptc_get_references(&RETVAL, label, self)) {
			RETVAL = -1;
			SET_ERRNUM(errno);
			SET_ERRSTR("%s", iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}
	OUTPUT:
	RETVAL

int
commit(self)
	IPTables::IPv4::Table	self
	CODE:
		RETVAL = iptc_commit(self);
		if(!RETVAL) {
			SET_ERRNUM(errno);
			SET_ERRSTR("%s", iptc_strerror(errno));
			SvIOK_on(ERROR_SV);
		}
		*self = NULL;
		
	OUTPUT:
	RETVAL

void
DESTROY(self)
	IPTables::IPv4::Table	&self
	CODE:
		if(self && *self) {
			if(!iptc_commit(self)) {
				fprintf(stderr, "Commit failed: %s\n",
						iptc_strerror(errno));
			}
		}
		/* vim: ts=4
		 */
