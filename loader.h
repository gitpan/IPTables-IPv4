#include "module_iface.h"
#include "libiptc/libiptc.h"

#define STD_TARGET "standard"
#define MATCH_RAW_POSTFIX "-match-raw"
#define TARGET_RAW_POSTFIX "-target-raw"

ModuleDef *ipt_find_module(char *, ModuleType, iptc_handle_t *);
