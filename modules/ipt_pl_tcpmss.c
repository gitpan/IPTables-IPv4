#define __USE_GNU
#include "../module_iface.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <netdb.h>
#include <linux/netfilter_ipv4/ipt_tcpmss.h>

#define MODULE_TYPE MODULE_MATCH
#define MODULE_DATATYPE struct ipt_tcpmss_match_info
#define MODULE_NAME "tcpmss"

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
	*nfcache |= NFC_IP_PROTO_UNKNOWN;
}

static int parse_field(char *field, SV *value, void *myinfo,
		unsigned int *nfcache, struct ipt_entry *entry, int *flags) {
	MODULE_DATATYPE *info = (void *)(*(MODULE_ENTRYTYPE **)myinfo)->data;
	char *sep, *extent, *temp, *str, *base;
	int val;
	struct protoent *proto;
	STRLEN len;

	if(strcmp(field, "mss"))
		return(FALSE);

	*flags = 1;

	proto = getprotobynumber(entry->ip.proto);
	if(!proto || strcmp(proto->p_name, "tcp") ||
					entry->ip.invflags & IPT_INV_PROTO) {
		SET_ERRSTR("%s: Protocol must be TCP", field);
		return(FALSE);
	}

	if(SvIOK(value)) {
		val = SvIV(value);
		if(val < 0 || val > USHRT_MAX) {
			SET_ERRSTR("%s: Value out of range", field);
			return(FALSE);
		}
		info->mss_min = info->mss_max = val;
	}
	else if(SvPOK(value)) {
		temp = SvPV(value, len);
		base = str = malloc(len + 1);
		strncpy(str, temp, len);
		str[len] = '\0';
		if(*str == INVCHAR) {
			info->invert = TRUE;
			str++;
		}

		sep = strchr(str, ':');
		val = strtoul(str, &extent, 10);
		if(extent < (sep ? sep : str + strlen(str)) || val < 0 ||
						val > USHRT_MAX) {
			SET_ERRSTR("%s: Unable to parse '%s'", field, str);
			free(base);
			return(FALSE);
		}
		info->mss_min = val;

		if(sep) {
			sep++;
			val = strtoul(sep, &extent, 10);
			if(extent < sep + strlen(sep) || val < 0 || val > USHRT_MAX) {
				SET_ERRSTR("%s: Unable to parse '%s'", field, str);
				free(base);
				return(FALSE);
			}
		}
		free(base);
		info->mss_max = val;
	}
	else {
		SET_ERRSTR("%s: Must be passed as integer or string", field);
		return(FALSE);
	}

	return(TRUE);
}

static void get_fields(HV *ent_hash, void *myinfo, struct ipt_entry *entry) {
	MODULE_DATATYPE *info = (void *)((MODULE_ENTRYTYPE *)myinfo)->data;
	char *string, *temp;

	asprintf(&string, "%u", info->mss_min);
	if(info->mss_min != info->mss_max) {
		asprintf(&temp, "%s:%u", string, info->mss_max);
		free(string);
		string = temp;
	}
	if(info->invert) {
		asprintf(&temp, "%c%s", INVCHAR, string);
		free(string);
		string = temp;
	}
	hv_store(ent_hash, "mss", 3, newSVpv(string, 0), 0);
	free(string);
}

static int final_check(void *myinfo, int flags) {
	if(!flags) {
		SET_ERRSTR("tcpmss match requires mss field");
		return(FALSE);
	}
	return(TRUE);
}

static ModuleDef _module = {
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
	return(&_module);
}
/* vim: ts=4
 */
