

EWDK_PATH := ../

EWDK_INC := "$(EWDK_PATH)/ewdk/Program Files/Windows Kits/10/Include"

TRANS_SRC := drbd/
TRANS_DEST := converted-sources/
WIN4LIN := win4lin/

TRANSFORMATIONS := $(sort $(wildcard transform.d/*))
ORIG := $(shell find $(TRANS_SRC) -name "*.[ch]" | egrep -v 'drbd/drbd-kernel-compat|drbd_transport_tcp.c|drbd_polymorph_printk.h|drbd_buildtag.c|drbd_transport_template.c')
TRANSFORMED := $(patsubst $(TRANS_SRC)%,$(TRANS_DEST)%,$(ORIG))

export SHELL=bash

all: build

# can not regenerate those scripts
$(TRANSFORMATIONS): ;

# can not regenerate the originals
$(ORIG): ;

$(TRANSFORMED): $(TRANSFORMATIONS) Makefile transform

$(TRANS_DEST)% : $(TRANS_SRC)%
	@./transform $< $@

$(TRANS_DEST).generated: $(ORIG)
	echo $(TRANSFORMED) > $(TRANS_DEST).generated

trans: $(TRANSFORMED) $(TRANS_DEST).generated

CP := cp --preserve=timestamps

patch: trans
	echo "const char *drbd_buildtag(void){return \"WDRBD: `git describe --tags --always --dirty`\";}" > $(TRANS_DEST)/drbd/drbd_buildtag.c
	$(CP) ./Makefile.win $(TRANS_DEST)/drbd/Makefile
	$(CP) ./ms-cl.cmd $(TRANS_DEST)/drbd/
	$(CP) ./windows/drbd_polymorph_printk.h $(TRANS_DEST)/drbd/
	$(CP) ./windows/drbd_proc.c $(TRANS_DEST)/drbd/
	$(CP) ./windows/drbd_transport_tcp.c $(TRANS_DEST)/drbd/

ifeq ($(shell uname -o),Cygwin)
build:
	@if test -d $(TRANS_DEST); then \
		cd $(TRANS_DEST)/drbd/ && $(MAKE); \
	else \
		echo "Please run 'make' first on a Linux system with spatch installed"; \
	fi
else
build: patch
	@echo "Now please run 'make' in the Windows VM."
endif
	

clean:
	if test -f $(TRANS_DEST)/.generated; then \
		rm -f $(shell cat $(TRANS_DEST).generated) $(TRANS_DEST).generated; \
		for d in $(TRANS_DEST) $(WIN4LIN); do \
			find $$d -name "*.tmp.bak" -delete; \
			find $$d -name "*.pdb" -delete; \
			find $$d -name "*.obj" -delete; \
			find $$d -name "*.orig" -delete; \
			find $$d -name "*.tmpe" -delete; \
		done; \
	fi

# vim: set ts=8 sw=8 noet : 
