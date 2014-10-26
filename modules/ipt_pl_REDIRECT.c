#define __USE_GNU
#include "../module_iface.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ip_nat.h>
#include <netdb.h>

#define MODULE_TYPE MODULE_TARGET
#define MODULE_DATATYPE struct ip_nat_multi_range
#define MODULE_NAME "REDIRECT"

#if MODULE_TYPE == MODULE_TARGET
#  define MODULE_ENTRYTYPE struct ipt_entry_match
#else 
#  if MODULE_TYPE == MODULE_MATCH
#    define MODULE_ENTRYTYPE struct ipt_entry_target
#  else
#    error MODULE_TYPE is unknown!
#  endif
#endif

static void setup(void *myinfo, unsigned int *nfcache) {
	MODULE_DATATYPE *info = (void *)((MODULE_ENTRYTYPE *)myinfo)->data;

	info->rangesize = 1;
	*nfcache |= NFC_UNKNOWN;
}

static int parse_nat_range(char *string, struct ip_nat_range *range,
		struct ipt_entry *entry) {
	char *sep, *extent, *temp;
	int port;
	struct protoent *proto = getprotobynumber(entry->ip.proto);

	if(strcmp(proto->p_name, "tcp") && strcmp(proto->p_name, "udp")) {
		SET_ERRSTR("to-ports: Protocol must be TCP or UDP to specify ports");
		return(FALSE);
	}
	
	sep = strchr(string, '-');

	port = strtoul(string, &extent, 10);
	if(extent < (sep ? sep : (string + strlen(string))) || port == 0 ||
					port > USHRT_MAX)
		return(FALSE);

	range->min.tcp.port = range->max.tcp.port = htons(port);

	if(sep) {
		temp = sep + 1;
		port = strtoul(temp, &extent, 10);

		if(extent < (temp + strlen(temp)) || port == 0 || port > USHRT_MAX ||
						port < range->min.tcp.port)
			return(FALSE);

		range->max.tcp.port = htons(port);
	}

	return(TRUE);
}

static int parse_field(char *field, SV *value, void *myinfo,
		unsigned int *nfcache, struct ipt_entry *entry, int *flags) {
	MODULE_DATATYPE *info = (void *)(*(MODULE_ENTRYTYPE **)myinfo)->data;
	
	if(strcmp(field, "to-ports"))
		return(FALSE);

	if(SvIOK(value))
		info->range->min.tcp.port = info->range->max.tcp.port = 
				htons(SvIV(value));
	else if(SvPOK(value)) {
		char *str, *temp;
		STRLEN len;

		temp = SvPV(value, len);
		str = malloc(len + 1);
		strncpy(str, temp, len);
		str[len] = '\0';

		if(!parse_nat_range(str, info->range, entry)) {
			if(!strcmp(SvPV_nolen(ERROR_SV), ""))
				SET_ERRSTR("%s: Unable to parse value", field);
			free(str);
			return(FALSE);
		}
		free(str);
	}
	else {
		SET_ERRSTR("%s: Arg must be string or integer", field);
		return(FALSE);
	}

	info->range->flags |= IP_NAT_RANGE_PROTO_SPECIFIED;

	return(TRUE);
}

static SV *sv_from_nat_range(struct ip_nat_range *range) {
	char *string;
	
	if(range->flags & IP_NAT_RANGE_PROTO_SPECIFIED) {
		SV *sv;
		if(range->min.tcp.port < range->max.tcp.port) {
			asprintf(&string, "%u-%u", ntohs(range->min.tcp.port),
							ntohs(range->max.tcp.port));
			sv = newSVpv(string, 0);
			free(string);
		}
		else
			sv = newSViv(ntohs(range->min.tcp.port));
		return sv;
	}
	return(NULL);
}

static void get_fields(HV *ent_hash, void *myinfo, struct ipt_entry *entry) {
	MODULE_DATATYPE *info = (void *)((MODULE_ENTRYTYPE *)myinfo)->data;
	SV *sv;

	if((sv = sv_from_nat_range(info->range)))
		hv_store(ent_hash, "to-ports", 8, sv, 0);
}

ModuleDef _module = {
	NULL, /* always NULL */
	MODULE_TYPE,
	MODULE_NAME,
	IPT_ALIGN(sizeof(MODULE_DATATYPE)),
	IPT_ALIGN(sizeof(MODULE_DATATYPE)),
	setup,
	parse_field,
	get_fields,
	NULL /* final_check */
};

ModuleDef *init(void) {
	return(&_module);
}
/* vim: ts=4
 */
