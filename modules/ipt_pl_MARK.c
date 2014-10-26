#define __USE_GNU
#include "../module_iface.h"
#include <string.h>
#include <stdio.h>
#include <linux/netfilter_ipv4/ipt_MARK.h>

#define MODULE_TYPE MODULE_TARGET
#define MODULE_DATATYPE struct ipt_mark_target_info
#define MODULE_NAME "MARK"

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

	if(strcmp(field, "set-mark"))
		return(FALSE);

	*flags = 1;

	if(SvIOK(value))
		info->mark = SvIV(value);
	else if(SvPOK(value)) {
		char *markstr, *extent, *temp;
		int num;
		STRLEN len;

		temp = SvPV(value, len);
		markstr = malloc(len + 1);
		strncpy(markstr, temp, len);
		markstr[len] = '\0';
		
		num = strtoul(markstr, &extent, 0);
		if(extent < markstr + strlen(markstr)) {
			SET_ERRSTR("%s: Unable to parse", field);
			free(markstr);
			return(FALSE);
		}
		free(markstr);
		info->mark = num;
	}
	else {
		SET_ERRSTR("%s: Must have a string or integer arg", field);
		return(FALSE);
	}

	return(TRUE);
}

static void get_fields(HV *ent_hash, void *myinfo, struct ipt_entry *entry) {
	MODULE_DATATYPE *info = (void *)((MODULE_ENTRYTYPE *)myinfo)->data;

	hv_store(ent_hash, "set-mark", 8, newSViv(info->mark), 0);
}

int final_check(void *myinfo, int flags) {
	if(!flags) {
		SET_ERRSTR("MARK target requires 'set-mark'");
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
	NULL /* setup */,
	parse_field,
	get_fields,
	final_check
};

ModuleDef *init(void) {
	return(&_module);
}
/* vim: ts=4
 */
