#include "../module_iface.h"

#define MODULE_TYPE MODULE_TARGET
#define MODULE_DATATYPE int
#define MODULE_NAME "IPV4OPTSSTRIP"

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

ModuleDef _module = {
	NULL, /* always NULL */
	MODULE_TYPE,
	MODULE_NAME,
	IPT_ALIGN(sizeof(MODULE_DATATYPE)),
	IPT_ALIGN(sizeof(MODULE_DATATYPE)),
	setup,
	NULL,
	NULL,
	NULL
};

ModuleDef *init(void) {
	return(&_module);
}
/* vim: ts=4
 */
