#define __USE_GNU
#include "../module_iface.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <linux/netfilter_ipv4/ipt_owner.h>

#define MODULE_TYPE MODULE_MATCH
#define MODULE_DATATYPE struct ipt_owner_info
#define MODULE_NAME "owner"

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
	char  *str, *base, *temp, *extent;
	STRLEN len;

	if(!strcmp(field, "uid-owner")) {
		if(SvIOK(value))
			info->uid = SvIV(value);
		else if(SvPOK(value)) {
			struct passwd *pwd;

			temp = SvPV(value, len);
			base = str = malloc(len + 1);
			strncpy(str, temp, len);
			str[len] = '\0';
			if(str[0] == INVCHAR) {
				info->invert |= IPT_OWNER_UID;
				str++;
			}
			if((pwd = getpwnam(str)))
				info->uid = pwd->pw_uid;
			else {
				info->uid = strtoul(str, &extent, 10);
				if(str + strlen(str) > extent) {
					SET_ERRSTR("%s: Couldn't parse uid '%s'", field, str);
					free(base);
					return(FALSE);
				}
			}
			free(base);
		}
		else {
			SET_ERRSTR("%s: Must have an integer or string value", field);
			return(FALSE);
		}
		info->match |= IPT_OWNER_UID;
	}
	else if(!strcmp(field, "gid-owner")) {
		if(SvIOK(value))
			info->gid = SvIV(value);
		else if(SvPOK(value)) {
			struct group *grp;

			temp = SvPV(value, len);
			base = str = malloc(len + 1);
			strncpy(str, temp, len);
			str[len] = '\0';
			if(str[0] == INVCHAR) {
				info->invert |= IPT_OWNER_GID;
				str++;
			}
			if((grp = getgrnam(str)))
				info->gid = grp->gr_gid;
			else {
				info->gid = strtoul(str, &extent, 10);
				if(str + strlen(str) > extent) {
					SET_ERRSTR("%s: Couldn't parse gid '%s'", field, str);
					free(base);
					return(FALSE);
				}
			}
			free(base);
		}
		else {
			SET_ERRSTR("%s: Must have an integer or string value", field);
			return(FALSE);
		}
		info->match |= IPT_OWNER_GID;
	}
	else if(!strcmp(field, "pid-owner")) {
		if(SvIOK(value))
			info->pid = SvIV(value);
		else if(SvPOK(value)) {
			temp = SvPV(value, len);
			base = str = malloc(len + 1);
			strncpy(str, temp, len);
			str[len] = '\0';
			if(str[0] == INVCHAR) {
				info->invert |= IPT_OWNER_PID;
				str++;
			}
			info->pid = strtoul(str, &extent, 10);
			if(str + strlen(str) > extent) {
				SET_ERRSTR("%s: Couldn't parse pid '%s'", field, str);
				free(base);
				return(FALSE);
			}
			free(base);
		}
		else {
			SET_ERRSTR("%s: Must have an integer or string value", field);
			return(FALSE);
		}
		info->match |= IPT_OWNER_PID;
	}
	else if(!strcmp(field, "sid-owner")) {
		if(SvIOK(value))
			info->sid = SvIV(value);
		else if(SvPOK(value)) {
			temp = SvPV(value, len);
			base = str = malloc(len + 1);
			strncpy(str, temp, len);
			str[len] = '\0';
			if(str[0] == INVCHAR) {
				info->invert |= IPT_OWNER_SID;
				str++;
			}
			info->sid = strtoul(str, &extent, 10);
			if(str + strlen(str) > extent) {
				SET_ERRSTR("%s: Couldn't parse sid '%s'", field, str);
				free(base);
				return(FALSE);
			}
			free(base);
		}
		else {
			SET_ERRSTR("%s: Must have an integer or string value", field);
			return(FALSE);
		}
		info->match |= IPT_OWNER_SID;
	}
	else
		return(FALSE);

	if(*flags) {
		SET_ERRSTR("%s: Only one of 'uid-owner', 'gid-owner', 'pid-owner', "
						"'sid-owner' allowed with owner match", field);
		return(FALSE);
	}
	*flags = 1;
	
	return(TRUE);
}

static void get_fields(HV *ent_hash, void *myinfo, struct ipt_entry *entry) {
	MODULE_DATATYPE *info = (void *)((MODULE_ENTRYTYPE *)myinfo)->data;
	char *name, *temp;
	SV *sv;
	
	if(info->match & IPT_OWNER_UID) {
		struct passwd *pwd;
		pwd = getpwuid(info->uid);
		if(pwd) {
			name = strdup(pwd->pw_name);
			if(info->invert & IPT_OWNER_UID) {
				asprintf(&temp, "%c%s", INVCHAR, name);
				free(name);
				name = temp;
			}
			sv = newSVpv(name, 0);
			free(name);
		}
		else if(info->invert & IPT_OWNER_UID) {
			asprintf(&name, "%c%u", INVCHAR, info->uid);
			sv = newSVpv(name, 0);
			free(name);
		}
		else
			sv = newSViv(info->uid);
		hv_store(ent_hash, "uid-owner", 9, sv, 0);
	}
	if(info->match & IPT_OWNER_GID) {
		struct group *grp;
		grp = getgrgid(info->gid);
		if(grp) {
			name = strdup(grp->gr_name);
			if(info->invert & IPT_OWNER_GID) {
				asprintf(&temp, "%c%s", INVCHAR, name);
				free(name);
				name = temp;
			}
			sv = newSVpv(name, 0);
			free(name);
		}
		else if(info->invert & IPT_OWNER_GID) {
			asprintf(&name, "%c%u", INVCHAR, info->gid);
			sv = newSVpv(name, 0);
			free(name);
		}
		else 
			sv = newSViv(info->gid);
		hv_store(ent_hash, "gid-owner", 9, sv, 0);
	}
	if(info->match & IPT_OWNER_PID) {
		if(info->invert & IPT_OWNER_PID) {
			asprintf(&name, "%c%u", INVCHAR, info->pid);
			sv = newSVpv(name, 0);
			free(name);
		}
		else 
			sv = newSViv(info->pid);
		hv_store(ent_hash, "pid-owner", 9, sv, 0);
	}
	if(info->match & IPT_OWNER_SID) {
		if(info->invert & IPT_OWNER_SID) {
			asprintf(&name, "%c%u", INVCHAR, info->sid);
			sv = newSVpv(name, 0);
			free(name);
		}
		else 
			sv = newSViv(info->sid);
		hv_store(ent_hash, "sid-owner", 9, sv, 0);
	}
}

int final_check(void *myinfo, int flags) {
	if(!flags) {
		SET_ERRSTR("owner must have one of 'uid-owner', 'gid-owner', "
						"'pid-owner', 'sid-owner'");
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
