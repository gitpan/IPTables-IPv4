#define __USE_GNU
#include "../module_iface.h"
#include <string.h>
#include <stdio.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_ipv4options.h>

#define MODULE_TYPE MODULE_MATCH
#define MODULE_DATATYPE struct ipt_ipv4options_info
#define MODULE_NAME "ipv4options"

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
	*nfcache |= NFC_UNKNOWN;
}

static int parse_field(char *field, SV *value, void *myinfo,
		unsigned int *nfcache, struct ipt_entry *entry, int *flags) {
	MODULE_DATATYPE *info = (void *)(*(MODULE_ENTRYTYPE **)myinfo)->data;

	if(!strcmp(field, "ssrr")) {
		if(*flags & IPT_IPV4OPTION_MATCH_LSRR) {
			SET_ERRSTR("%s: Can't use both 'ssrr' and 'lsrr' with ipv4options "
							"match", field);
			return(FALSE);
		}
		else if(*flags & IPT_IPV4OPTION_DONT_MATCH_SRR) {
			SET_ERRSTR("%s: Can't use both 'ssrr' and 'no-srr' with "
							"ipv4options match", field);
			return(FALSE);
		}
		info->options |= IPT_IPV4OPTION_MATCH_SSRR;
		*flags |= IPT_IPV4OPTION_MATCH_SSRR;
	}
	else if(!strcmp(field, "lsrr")) {
		if(*flags & IPT_IPV4OPTION_MATCH_SSRR) {
			SET_ERRSTR("%s: Can't use both 'lsrr' and 'ssrr' with ipv4options "
							"match", field);
			return(FALSE);
		}
		else if(*flags & IPT_IPV4OPTION_DONT_MATCH_SRR) {
			SET_ERRSTR("%s: Can't use both 'lsrr' and 'no-srr' with "
							"ipv4options match", field);
			return(FALSE);
		}
		info->options |= IPT_IPV4OPTION_MATCH_LSRR;
		*flags |= IPT_IPV4OPTION_MATCH_LSRR;
	}
	else if(!strcmp(field, "no-srr")) {
		if(*flags & IPT_IPV4OPTION_MATCH_SSRR) {
			SET_ERRSTR("%s: Can't use both 'no-srr' and 'ssrr' with "
							"ipv4options match", field);
			return(FALSE);
		}
		else if(*flags & IPT_IPV4OPTION_MATCH_LSRR) {
			SET_ERRSTR("%s: Can't use both 'no-srr' and 'lsrr' with "
							"ipv4options match", field);
			return(FALSE);
		}
		info->options |= IPT_IPV4OPTION_DONT_MATCH_SRR;
		*flags |= IPT_IPV4OPTION_DONT_MATCH_SRR;
	}
	else if(!strcmp(field, "rr")) {
		if(SvIOK(value)) {
			if(SvIV(value)) {
				info->options |= IPT_IPV4OPTION_MATCH_RR;
				*flags |= IPT_IPV4OPTION_MATCH_RR;
			}
			else {
				info->options |= IPT_IPV4OPTION_DONT_MATCH_RR;
				*flags |= IPT_IPV4OPTION_DONT_MATCH_RR;
			}
		}
		else {
			SET_ERRSTR("%s: Must have an integer arg", field);
			return(FALSE);
		}
	}
	else if(!strcmp(field, "ts")) {
		if(SvIOK(value)) {
			if(SvIV(value)) {
				info->options |= IPT_IPV4OPTION_MATCH_TIMESTAMP;
				*flags |= IPT_IPV4OPTION_MATCH_TIMESTAMP;
			}
			else {
				info->options |= IPT_IPV4OPTION_DONT_MATCH_TIMESTAMP;
				*flags |= IPT_IPV4OPTION_DONT_MATCH_TIMESTAMP;
			}
		}
		else {
			SET_ERRSTR("%s: Must have an integer arg", field);
			return(FALSE);
		}
	}
	else if(!strcmp(field, "ra")) {
		if(SvIOK(value)) {
			if(SvIV(value)) {
				info->options |= IPT_IPV4OPTION_MATCH_ROUTER_ALERT;
				*flags |= IPT_IPV4OPTION_MATCH_ROUTER_ALERT;
			}
			else {
				info->options |= IPT_IPV4OPTION_DONT_MATCH_ROUTER_ALERT;
				*flags |= IPT_IPV4OPTION_DONT_MATCH_ROUTER_ALERT;
			}
		}
		else {
			SET_ERRSTR("%s: Must have an integer arg", field);
			return(FALSE);
		}
	}
	else if(!strcmp(field, "any-opt")) {
		if(SvIOK(value)) {
			if(SvIV(value)) {
				if((*flags & IPT_IPV4OPTION_DONT_MATCH_SRR) ||
				   (*flags & IPT_IPV4OPTION_DONT_MATCH_RR) ||
				   (*flags & IPT_IPV4OPTION_DONT_MATCH_TIMESTAMP) ||
				   (*flags & IPT_IPV4OPTION_DONT_MATCH_ROUTER_ALERT)) {
					SET_ERRSTR("%s: Can't use 'any-opt' and a negative option "
									"together with ipv4options", field);
					return(FALSE);
				}
				info->options |= IPT_IPV4OPTION_MATCH_ANY_OPT;
				*flags |= IPT_IPV4OPTION_MATCH_ANY_OPT;
			}
			else {
				if((*flags & IPT_IPV4OPTION_MATCH_LSRR) ||
				   (*flags & IPT_IPV4OPTION_MATCH_SSRR) ||
				   (*flags & IPT_IPV4OPTION_MATCH_RR) ||
				   (*flags & IPT_IPV4OPTION_MATCH_TIMESTAMP) ||
				   (*flags & IPT_IPV4OPTION_MATCH_ROUTER_ALERT)) {
					SET_ERRSTR("%s: Can't use a negative 'any-opt' and a "
									"positive option together with ipv4options",
									field);
					return(FALSE);
				}
				info->options |= IPT_IPV4OPTION_DONT_MATCH_ROUTER_ALERT;
				*flags |= IPT_IPV4OPTION_DONT_MATCH_ROUTER_ALERT;
			}
		}
		else {
			SET_ERRSTR("%s: Must have an integer arg", field);
			return(FALSE);
		}
	}
	else
		return(FALSE);

	return(TRUE);
}

static void get_fields(HV *ent_hash, void *myinfo, struct ipt_entry *entry) {
	MODULE_DATATYPE *info = (void *)((MODULE_ENTRYTYPE *)myinfo)->data;

	if(info->options & IPT_IPV4OPTION_MATCH_SSRR)
		hv_store(ent_hash, "ssrr", 4, newSViv(1), 0);
	else if(info->options & IPT_IPV4OPTION_MATCH_LSRR)
		hv_store(ent_hash, "lsrr", 4, newSViv(1), 0);
	else if(info->options & IPT_IPV4OPTION_DONT_MATCH_SRR)
		hv_store(ent_hash, "no-srr", 6, newSViv(1), 0);
	if(info->options & IPT_IPV4OPTION_MATCH_RR)
		hv_store(ent_hash, "rr", 2, newSViv(1), 0);
	else if(info->options & IPT_IPV4OPTION_DONT_MATCH_RR)
		hv_store(ent_hash, "rr", 2, newSViv(0), 0);
	if(info->options & IPT_IPV4OPTION_MATCH_TIMESTAMP)
		hv_store(ent_hash, "ts", 2, newSViv(1), 0);
	else if(info->options & IPT_IPV4OPTION_DONT_MATCH_TIMESTAMP)
		hv_store(ent_hash, "ts", 2, newSViv(0), 0);
	if(info->options & IPT_IPV4OPTION_MATCH_ROUTER_ALERT)
		hv_store(ent_hash, "ra", 2, newSViv(1), 0);
	else if(info->options & IPT_IPV4OPTION_DONT_MATCH_ROUTER_ALERT)
		hv_store(ent_hash, "ra", 2, newSViv(0), 0);
	if(info->options & IPT_IPV4OPTION_MATCH_ANY_OPT)
		hv_store(ent_hash, "any-opt", 7, newSViv(1), 0);
	else if(info->options & IPT_IPV4OPTION_DONT_MATCH_ANY_OPT)
		hv_store(ent_hash, "any-opt", 7, newSViv(0), 0);
}

int final_check(void *myinfo, int flags) {
	if(!flags) {
		SET_ERRSTR("ipv4options match requires one or more of 'ssrr', 'lsrr', "
						"'no-srr', 'rr', 'ts', 'ra', 'any-opt'");
		return(FALSE);
	}
	
	return(TRUE);
}

static ModuleDef DSCP_module = {
	NULL, /* always NULL */
	MODULE_TYPE,
	MODULE_NAME,
	IPT_ALIGN(sizeof(MODULE_DATATYPE)),
	IPT_ALIGN(sizeof(MODULE_DATATYPE)),
	setup,
	parse_field,
	get_fields,
	final_check
};

ModuleDef *init(void) {
	return(&DSCP_module);
}
/* vim: ts=4
 */
