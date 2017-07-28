VERSION=$(shell git describe --tags --always --dirty)
export TMPDIR = /tmp

TRANS_SRC := drbd/
TRANS_DEST := converted-sources/
WIN4LIN := win4lin/

TRANSFORMATIONS := $(sort $(wildcard transform.d/*))
ORIG := $(shell find $(TRANS_SRC) -name "*.[ch]" | egrep -v 'drbd/drbd-kernel-compat|drbd_transport_template.c|drbd_buildtag.c')
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

copy:
	$(CP) ./Makefile.win $(TRANS_DEST)/drbd/Makefile
	$(CP) ./ms-cl.cmd $(TRANS_DEST)/drbd/
	$(CP) ./INSTALL-DRBD*.bat $(TRANS_DEST)/drbd/

deps: copy trans
	cd $(TRANS_DEST)/drbd && $(MAKE) deps

patch: trans versioninfo copy

.PHONY: versioninfo
versioninfo:
	./versioninfo.sh $(TRANS_DEST) || true

define copy_win
	@mkdir $$(dirname $(2)) 2>/dev/null || true
	@rm -f $(2)
	@echo '#include "../../$(1)"' > $(2)
endef
$(TRANS_DEST)drbd/drbd_polymorph_printk.h: windows/drbd_polymorph_printk.h
	$(call copy_win,$<,$@)
$(TRANS_DEST)drbd/drbd_proc.c: windows/drbd_proc.c
	$(call copy_win,$<,$@)
$(TRANS_DEST)drbd/drbd_transport_tcp.c: windows/drbd_transport_wtcp.c
	$(call copy_win,$<,$@)

ifeq ($(shell uname -o),Cygwin)
build: patch
	@if test -d $(TRANS_DEST); then \
		cd $(TRANS_DEST)/drbd/ && $(MAKE); \
	else \
		echo "Please run 'make' first on a Linux system with spatch installed"; \
	fi

install: build
	@if test -d $(TRANS_DEST); then \
		cd $(TRANS_DEST)/drbd/ && $(MAKE) install; \
	else \
		echo "Please run 'make' first on a Linux system with spatch installed"; \
	fi
else
build: patch
	@echo "Now please run 'make' in the Windows VM."

install:
	@echo "This is not a Windows machine. Since we are building a Windows"
	@echo "kernel driver, execute make install on your Windows box (as"
	@echo "Administrator)"

endif
	
tarball:
	rm -rf $(TRANS_DEST) && mkdir $(TRANS_DEST)
	make trans # regenerate cocci-cache
	rm -rf $(TRANS_DEST) && mkdir $(TRANS_DEST)
	make versioninfo
	git ls-files > .filelist
	find $(TRANS_DEST) -print >> .filelist
	find transform.d/cocci-cache -print >> .filelist
	sed -i "s/^/wdrbd-$(VERSION)\//" .filelist
	ln -s . wdrbd-$(VERSION)
	tar --owner=0 --group=0 -czf - -T .filelist > wdrbd-$(VERSION).tar.gz
	rm wdrbd-$(VERSION)

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
