#ifndef _MODULE_IFACE_H
#define _MODULE_IFACE_H

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <libiptc/libiptc.h>

#ifndef MODULE_PATH
# define MODULE_PATH "/usr/local/lib/IPTables-IPv4"
#endif /* MODULE_PATH */
#define INVCHAR '!'
#define ERROR_SV perl_get_sv("!", 0)
#define SET_ERRSTR(format...) sv_setpvf(ERROR_SV, ##format)
#define SET_ERRNUM(value) sv_setiv(ERROR_SV, (IV)value)

typedef enum {
	MODULE_MATCH,
	MODULE_TARGET
} ModuleType;

typedef struct {
	/* Point to next in line - this should start out NULL */
	void *next;
	
	/* What kind of module am I? */
	ModuleType type;

	/* What's my name? */
	ipt_chainlabel name;

	/* Match data field size */
	size_t size;

	/* Size for comparison in userspace */
	size_t size_uspace;

	/* Setup the module's information */
	void (*setup)(void *myinfo, unsigned int *nfcache);

	/* Take a field name and a value, and if the field name is ours,
	 * then munch down that value and stuff it into its appropriate
	 * place (return TRUE to indicate it was ours, FALSE if not) */
	int (*parse_field)(char *field, SV *value, void *myinfo,
			unsigned int *nfcache, struct ipt_entry *entry,
			int *flags);

	/* Take a match/target entry that belongs to us, and add all the
	 * relevant fields into the hash */
	void (*get_fields)(HV *ent_hash, void *myinfo, struct ipt_entry *entry);

	/* Do some last-minute checks on the packed data structure, and
	 * return TRUE if everything checks out, FALSE if not */
	int (*final_check)(void *myinfo, int flags);
} ModuleDef;

#endif /* _MODULE_IFACE_H */
