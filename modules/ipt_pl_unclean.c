#include "../module_iface.h"

#define MODULE_TYPE MODULE_MATCH
#define MODULE_DATATYPE void
#define MODULE_NAME "unclean"

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

ModuleDef unclean_module = {
	NULL, /* always NULL */
	MODULE_TYPE,
	MODULE_NAME,
	IPT_ALIGN(0),
	IPT_ALIGN(0),
	setup,
	NULL /* parse_field */,
	NULL /* get_fields */,
	NULL /* final_check */
};

ModuleDef *init(void) {
	return(&unclean_module);
}
/* vim: ts=4
 */
