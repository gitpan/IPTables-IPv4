#include "../module_iface.h"

#define MODULE_TYPE MODULE_TARGET
#define MODULE_DATATYPE void
#define MODULE_NAME "MIRROR"

#if MODULE_TYPE == MODULE_TARGET
#  define MODULE_ENTRYTYPE struct ipt_entry_match
#else 
#  if MODULE_TYPE == MODULE_MATCH
#    define MODULE_ENTRYTYPE struct ipt_entry_target
#  else
#    error MODULE_TYPE is unknown!
#  endif
#endif

ModuleDef _module = {
	NULL, /* always NULL */
	MODULE_TYPE,
	MODULE_NAME,
	IPT_ALIGN(0),
	IPT_ALIGN(0),
	NULL,
	NULL,
	NULL,
	NULL
};

ModuleDef *init(void) {
	return(&_module);
}

/* vim: ts=4
 */
