#define __USE_GNU
#include "../module_iface.h"
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_FTOS.h>

#define MODULE_TYPE MODULE_TARGET
#define MODULE_DATATYPE struct ipt_FTOS_info
#define MODULE_NAME "FTOS"

#if MODULE_TYPE == MODULE_TARGET
#  define MODULE_ENTRYTYPE struct ipt_entry_match
#else 
#  if MODULE_TYPE == MODULE_MATCH
#    define MODULE_ENTRYTYPE struct ipt_entry_target
#  else
#    error MODULE_TYPE is unknown!
#  endif
#endif

static int parse_field(char *field, SV *value, void *myinfo,
		unsigned int *nfcache, struct ipt_entry *entry, int *flags) {
	MODULE_DATATYPE *info = (void *)(*(MODULE_ENTRYTYPE **)myinfo)->data;
	int tosval;
	
	if(strcmp(field, "set-ftos"))
		return(FALSE);

	*flags = 1;

	if(!SvIOK(value)) {
		SET_ERRSTR("%s: Must have an integer arg", field);
		return(FALSE);
	}
	else
		tosval = SvIV(value);

	if(tosval < 0 || tosval > UCHAR_MAX) {
		SET_ERRSTR("%s: Value out of range", field);
		return(FALSE);
	}

	info->ftos = tosval;
	return(TRUE);
}

static void get_fields(HV *ent_hash, void *myinfo, struct ipt_entry *entry) {
	MODULE_DATATYPE *info = (void *)((MODULE_ENTRYTYPE *)myinfo)->data;

	hv_store(ent_hash, "set-ftos", 8, newSViv(info->ftos), 0);
}

static int final_check(void *myinfo, int flags) {
	if(!flags) {
		SET_ERRSTR("FTOS target requires set-ftos field");
		return(FALSE);
	}

	return(TRUE);
}

ModuleDef _module = {
	NULL, /* always NULL */
	MODULE_TYPE,
	MODULE_NAME,
	IPT_ALIGN(sizeof(MODULE_DATATYPE)),
	IPT_ALIGN(sizeof(MODULE_DATATYPE)),
	NULL, /* setup */
	parse_field,
	get_fields,
	final_check
};

ModuleDef *init(void) {
	return(&_module);
}
/* vim: ts=4
 */
