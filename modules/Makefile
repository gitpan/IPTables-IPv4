CC := gcc
LD := ld
STRIP := strip
RM := rm -f
INSTALL := install

KERNEL_BASE := /usr/src/linux
NF_BASE := ..
PERL_BASE := $(shell perl -e 'use Config; print $$Config{archlibexp}, "\n";')
INSTALL_BASE := $(shell perl -e 'use Config; print $$Config{siteprefixexp}, "\n";')

KERNEL_INC := $(KERNEL_BASE)/include
NF_INC := $(NF_BASE)/include
PERL_INC := $(PERL_BASE)/CORE
ifndef INSTALL_DIR
INSTALL_DIR := $(INSTALL_BASE)/lib/IPTables-IPv4
endif

CFLAGS := -I$(KERNEL_INC) -I$(NF_INC) -I$(PERL_INC) -I.. -Wall

# Basic protocol modules
MODULE_NAMES := icmp tcp udp
# Standard external targets
MODULE_NAMES += DNAT LOG MARK MASQUERADE MIRROR REDIRECT REJECT SNAT TOS standard
# Standard matches #
MODULE_NAMES += limit mac mark multiport owner state tos unclean

MODULE_NAMES += FTOS TCPMSS TTL ULOG DSCP ECN
MODULE_NAMES += tcpmss ttl ecn dscp iplimit

MODULE_NAMES += $(foreach T,$(wildcard ./.*-test),$(shell KERNEL_DIR=$(KERNEL_BASE) sh $(T)))

MODULE_LIST := $(foreach T,$(MODULE_NAMES),ipt_pl_$(T).so)

default: all

clean:
	-$(RM) *.so *.o

all: $(MODULE_LIST)
	@echo "Module build complete."

%.so: %.o
	$(LD) -shared -o $@ $<

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

strip: $(MODULE_LIST)
	$(STRIP) $^

install: all strip
	@echo "Installing modules in $(INSTALL_DIR):"
	$(INSTALL) -d -m 755 $(INSTALL_DIR)
	$(INSTALL) -m 644 $(MODULE_LIST) $(INSTALL_DIR)
