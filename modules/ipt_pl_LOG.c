#define __USE_GNU
#include "../module_iface.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <linux/netfilter_ipv4/ipt_LOG.h>

#define MODULE_TYPE MODULE_TARGET
#define MODULE_DATATYPE struct ipt_log_info
#define MODULE_NAME "LOG"

#if MODULE_TYPE == MODULE_TARGET
#  define MODULE_ENTRYTYPE struct ipt_entry_match
#else 
#  if MODULE_TYPE == MODULE_MATCH
#    define MODULE_ENTRYTYPE struct ipt_entry_target
#  else
#    error MODULE_TYPE is unknown!
#  endif
#endif

#define LOG_DEFAULT_LEVEL LOG_WARNING

typedef struct {
	char *name;
	unsigned int level;
} logLevel;

logLevel log_levels[] = {
	{ "alert",		LOG_ALERT },
	{ "crit",		LOG_CRIT },
	{ "debug",		LOG_DEBUG },
	{ "emerg",		LOG_EMERG },
	{ "error",		LOG_ERR },			/* deprecated */
	{ "info",		LOG_INFO },
	{ "notice",		LOG_NOTICE },
	{ "panic",		LOG_EMERG },		/* deprecated */
	{ "warning",	LOG_WARNING }
};

static void setup(void *myinfo, unsigned int *nfcache) {
	MODULE_DATATYPE *info = (void *)((MODULE_ENTRYTYPE *)myinfo)->data;

	info->level = LOG_DEFAULT_LEVEL;
	*nfcache |= NFC_UNKNOWN;
}

static int parse_field(char *field, SV *value, void *myinfo,
		unsigned int *nfcache, struct ipt_entry *entry, int *flags) {
	MODULE_DATATYPE *info = (void *)(*(MODULE_ENTRYTYPE **)myinfo)->data;
	char *temp = NULL, *str = NULL, *extent = NULL;
	int val, i;
	logLevel *selector = NULL;
	STRLEN len;

	if(!strcmp(field, "log-level")) {
		if(SvIOK(value)) {
			val = SvIV(value);
			if(val < 0 || val > 255) {
				SET_ERRSTR("%s: Value out of range", field);
				return(FALSE);
			}
			info->level = val;
		}
		else if(SvPOK(value)) {
			temp = SvPV(value, len);
			str = malloc(len + 1);
			strncpy(str, temp, len);
			str[len] = '\0';
			for(i = 0; i < sizeof(log_levels) / sizeof(logLevel); i++) {
				if(!strcmp(log_levels[i].name, str)) {
					selector = &log_levels[i];
					break;
				}
			}
			if(selector)
				info->level = selector->level;
			else {
				val = strtoul(str, &extent, 10);
				if(str + strlen(str) > extent) {
					SET_ERRSTR("%s: Unable to parse", field);
					goto pf_failed;
				}
				if(val < 0 || val > 255) {
					SET_ERRSTR("%s: Value out of range", field);
					goto pf_failed;
				}
				selector->level = val;
			}
		}
		else {
			SET_ERRSTR("%s: Must have a string or integer arg", field);
			goto pf_failed;
		}
	}
	else if(!strcmp(field, "log-prefix")) {
		if(!SvPOK(value)) {
			SET_ERRSTR("%s: Must have a string arg", field);
			goto pf_failed;
		}

		temp = SvPV(value, len);
		str = malloc(len + 1);
		strncpy(str, temp, len);
		str[len] = '\0';
		strncpy(info->prefix, str, 29);
		free(str);
	}
	else if(!strcmp(field, "log-tcp-sequence"))
		info->logflags |= IPT_LOG_TCPSEQ;
	else if(!strcmp(field, "log-tcp-options"))
		info->logflags |= IPT_LOG_TCPOPT;
	else if(!strcmp(field, "log-ip-options"))
		info->logflags |= IPT_LOG_IPOPT;
	else
		goto pf_failed;

	free(str);
	return(TRUE);
pf_failed:
	if(str)
		free(str);
	return(FALSE);
}

static void get_fields(HV *ent_hash, void *myinfo, struct ipt_entry *entry) {
	MODULE_DATATYPE *info = (void *)((MODULE_ENTRYTYPE *)myinfo)->data;
	logLevel *selector = NULL;
	int i;
	SV *sv;
	
	for(i = 0; i < sizeof(log_levels) / sizeof(logLevel); i++) {
		if(info->level == log_levels[i].level) {
			selector = &log_levels[i];
			break;
		}
	}

	if(selector)
		sv = newSVpv(selector->name, 0);
	else
		sv = newSViv(info->level);
	hv_store(ent_hash, "log-level", 9, sv, 0);

	if(strcmp(info->prefix, ""))
		hv_store(ent_hash, "log-prefix", 10, newSVpv(info->prefix, 0), 0);
	
	if(info->logflags & IPT_LOG_TCPSEQ)
		hv_store(ent_hash, "log-tcp-sequence", 16, newSViv(1), 0);
	if(info->logflags & IPT_LOG_TCPOPT)
		hv_store(ent_hash, "log-tcp-options", 15, newSViv(1), 0);
	if(info->logflags & IPT_LOG_IPOPT)
		hv_store(ent_hash, "log-ip-options", 14, newSViv(1), 0);
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
