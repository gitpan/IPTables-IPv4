/* This code unpacks a (struct ipt_entry) into a Perl hash, for passing to
 * a script for output and manipulation purposes.
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


#define __USE_GNU
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* for struct ipt_entry and co. */
#include <libiptc/libiptc.h>
/* for getprotobynumber() */
#include <netdb.h>
/* for inet_ntop() */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
/* for strtoul() */
#include <stdlib.h>
/* for ntohl() */
#include <netinet/in.h>

#include "unpacker.h"
#include "loader.h"
#include "module_iface.h"

/* Translate an address/netmask pair into a string */
static SV *addr_and_mask_to_sv(struct in_addr addr, struct in_addr mask,
		bool inv) {
	char *temp, *temp2, addrstr[INET_ADDRSTRLEN + 1];
	u_int32_t maskval;
	int i, maskwidth = 0, at_zeros = FALSE, contiguous = TRUE;
	SV *sv;

	/* We always translate the address into a string */
	inet_ntop(AF_INET, (void *)&addr, addrstr, INET_ADDRSTRLEN);
	temp = strdup(addrstr);
	maskval = ntohl(mask.s_addr);
	/* Do the magic work of converting the netmask to a width value, or a
	 * plain netmask, if it can't be stored as a width value */
	for(i = 31; i >= 0; i--) {
		if((maskval >> i) & 1) {
			maskwidth++;
			if(at_zeros)
				contiguous = FALSE;
		}
		else
			at_zeros = TRUE;
	}
	if(maskwidth < 32) {
		/* Ok, this is not a host entry */
		if(contiguous) /* If it was contiguous, it can be expressed
			        * as a single mask value */
			asprintf(&temp2, "%s/%u", temp, maskwidth);
		else { /* Otherwise, express it as a regular dotted-quad
		        * netmask value */
			inet_ntop(AF_INET, &mask.s_addr, addrstr,
					INET_ADDRSTRLEN);
			asprintf(&temp2, "%s/%s", temp, addrstr);
		}
		free(temp);
		temp = temp2;
	}
	if(inv) {
		asprintf(&temp2, "%c%s", INVCHAR, temp);
		free(temp);
		temp = temp2;
	}
	sv = newSVpv(temp, 0);
	free(temp);
	return(sv);
}

/* We have a job, kids - to turn a (struct ipt_entry *) into a hash... */
HV *ipt_do_unpack(struct ipt_entry *entry, iptc_handle_t *table) {
	SV *sv;
	HV *hash;
	AV *match_list = NULL;
	char *temp, *rawkey, *targetname = NULL, *protoname = NULL;
	struct protoent *protoinfo;
	ModuleDef *module = NULL;
	struct ipt_entry_match *match = NULL;
	struct ipt_entry_target *target = NULL;

	/* If the pointer is NULL, then we've got a slight problem. */
	if(!entry)
		return(NULL);
	
	hash = newHV();
	
	/* Ok, let's break this down point by point. First off, the source
	 * address... */
	if(entry->nfcache & NFC_IP_SRC) {
		sv = addr_and_mask_to_sv(entry->ip.src, entry->ip.smsk,
				entry->ip.invflags & IPT_INV_SRCIP);
		hv_store(hash, "source", 6, sv, 0);
	}
	
	/* Now, the destination address */
	if(entry->nfcache & NFC_IP_DST) {
		sv = addr_and_mask_to_sv(entry->ip.dst, entry->ip.dmsk,
				entry->ip.invflags & IPT_INV_DSTIP);
		hv_store(hash, "destination", 11, sv, 0);
	}
	
	/* Now, the packet incoming interface */
	if(entry->nfcache & NFC_IP_IF_IN) {
		char *ifname = strdup(entry->ip.iniface);
		if(entry->ip.invflags & IPT_INV_VIA_IN) {
			asprintf(&temp, "%c%s", INVCHAR, ifname);
			free(ifname);
			ifname = temp;
		}
		hv_store(hash, "in-interface", 12, newSVpv(ifname, 0), 0);
		free(ifname);
	}
	
	/* Packet outgoing interface */
	if(entry->nfcache & NFC_IP_IF_OUT) {
		char *ifname = strdup(entry->ip.outiface);
		if(entry->ip.invflags & IPT_INV_VIA_OUT) {
			asprintf(&temp, "%c%s", INVCHAR, ifname);
			free(ifname);
			ifname = temp;
		}
		hv_store(hash, "out-interface", 13, newSVpv(ifname, 0), 0);
		free(ifname);
	}
	
	/* Protocol */
	if(entry->nfcache & NFC_IP_PROTO) {
		char *protostr;
		if((protoinfo = getprotobynumber(entry->ip.proto))) {
			protostr = strdup(protoinfo->p_name);
			protoname = protostr;
			if(entry->ip.invflags & IPT_INV_PROTO) {
				asprintf(&temp, "%c%s", INVCHAR, protostr);
				free(protostr);
				protostr = temp;
				protoname = protostr + 1;
			}
			protoname = strdup(protoname);
			sv = newSVpv(protostr, 0);
			free(protostr);
		}
		else if(entry->ip.invflags & IPT_INV_PROTO) {
			asprintf(&protostr, "%c%u", INVCHAR, entry->ip.proto);
			sv = newSVpv(protostr, 0);
			free(protostr);
		}
		else
			sv = newSViv(entry->ip.proto);
		hv_store(hash, "protocol", 8, sv, 0);
	}

	/* Fragment flag */
	if(entry->ip.flags & IPT_F_FRAG) {
		hv_store(hash, "fragment", 8, newSViv(!(entry->ip.invflags &
										IPT_INV_FRAG)), 0);
	}
	
	/* Jump target */
	if((targetname = (char *)iptc_get_target(entry, table))) {
		target = (void *)entry + entry->target_offset;
		if(strcmp("", targetname))
			hv_store(hash, "jump", 4, newSVpv(targetname, 0), 0);

		module = ipt_find_module(targetname, MODULE_TARGET, table);
		/* If we didn't find a module for the target, stuff the raw target
		 * data into the hash with an appropriately-named key. */
		if(!module) {
			char *data;
			int data_size = target->u.target_size -
				IPT_ALIGN(sizeof(struct ipt_entry_target));
			if(data_size > 0) {
				asprintf(&rawkey, "%s" TARGET_RAW_POSTFIX, targetname);
				data = malloc(data_size);
				memcpy(data, target->data, data_size);
				hv_store(hash, rawkey, strlen(rawkey), newSVpv(data, data_size),
								0);
				free(rawkey);
				free(data);
			}
		}
		else if(module->get_fields)
			module->get_fields(hash, ((void *)entry + entry->target_offset),
							entry);
	}
	
	/* And now, iterate through the match modules */
	for(match = (void *)entry->elems;
			(void *)match < ((void *)entry + entry->target_offset);
			match = (void *)match + match->u.match_size) {
		/* If it's a protocol match, make sure it doesn't end up on the
		 * match list. */
		if(protoname ? strcmp(protoname, match->u.user.name) : TRUE) {
			/* If we haven't setup the match list already, create the array
			 * now. */
			if(!match_list)
				match_list = newAV();
			av_push(match_list, newSVpv(match->u.user.name, 0));
		}
		
		module = ipt_find_module(match->u.user.name, MODULE_MATCH, table);
		/* If we didn't find a module for the current match, stuff the raw
		 * match data into the hash with an appropriately-named key. */
		if(!module) {
			char *data;
			int data_size = match->u.match_size -
					IPT_ALIGN(sizeof(struct ipt_entry_match));
			asprintf(&rawkey, "%s" MATCH_RAW_POSTFIX, match->u.user.name);
			data = malloc(data_size);
			memcpy(data, match->data, data_size);
			hv_store(hash, rawkey, strlen(rawkey), newSVpv(data, data_size), 0);
			free(rawkey);
			free(data);
		}
		else if(module->get_fields)
			module->get_fields(hash, match, entry);
	}

	if(match_list)
		hv_store(hash, "matches", 7, newRV((SV *)match_list), 0);
	
	/* And the byte and packet counters */
	asprintf(&temp, "%llu", entry->counters.bcnt);
	hv_store(hash, "bcnt", 4, newSVpv(temp, 0), 0);
	free(temp);
	asprintf(&temp, "%llu", entry->counters.pcnt);
	hv_store(hash, "pcnt", 4, newSVpv(temp, 0), 0);
	free(temp);

	if(protoname)
		free(protoname);
	return hash;
}

/* vim: ts=4
 */
