VERSION=$(shell git describe --tags --always --dirty)
export TMPDIR = /tmp

COMPILE_USING_WINE=1

TRANS_SRC := drbd/
TRANS_DEST := converted-sources/
WIN4LIN := windrbd/

TRANSFORMATIONS := $(sort $(wildcard transform.d/*))
ORIG := $(shell find $(TRANS_SRC) -name "*.[ch]" | egrep -v 'drbd/drbd-kernel-compat|drbd_transport_template.c|drbd_buildtag.c|compat.h|drbd_polymorph_printk.h')
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
	$(CP) ./ms-cl*.cmd $(TRANS_DEST)/drbd/

deps: copy trans
	cd $(TRANS_DEST)/drbd && $(MAKE) deps

patch: trans versioninfo copy

.PHONY: versioninfo
versioninfo:
	./versioninfo.sh $(TRANS_DEST) || true

ifeq ($(shell uname -o),Cygwin)
build: 
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

package: build
	@if test -d $(TRANS_DEST); then \
		cd $(TRANS_DEST)/drbd/ && $(MAKE) package; \
	else \
		echo "Please run 'make' first on a Linux system with spatch installed"; \
	fi

signed-package:
	@if test -d $(TRANS_DEST); then \
		cd $(TRANS_DEST)/drbd/ && $(MAKE) signed-package; \
	else \
		echo "Please run 'make' first on a Linux system with spatch installed"; \
	fi

clean:
	for d in $(TRANS_DEST) $(WIN4LIN); do \
		find $$d -name "*.pdb" -delete; \
		find $$d -name "*.obj" -delete; \
		find $$d -name "windrbd.sys" -delete; \
		find $$d -name "windrbd.cat" -delete; \
		find $$d -name "_windrbd.ilk" -delete; \
	done
	make -C converted-sources/drbd/ clean

# Those 4 targets are for running static code verifiers
.PHONY: sdv dvl code-analysis codeql

sdv:
	cd $(TRANS_DEST)/drbd/ && $(MAKE) sdv

dvl:
	cd $(TRANS_DEST)/drbd/ && $(MAKE) dvl

code-analysis:
	cd $(TRANS_DEST)/drbd/ && $(MAKE) code-analysis

codeql:
	cd $(TRANS_DEST)/drbd/ && $(MAKE) codeql

# This is the target to procude a .DVL.XML suitable for Static
# tools logo test for Windows Server 2019 (and older systems)
server2019-dvl-rebuild:
	cd $(TRANS_DEST)/drbd/ && $(MAKE) server2019-dvl-rebuild

else

build: patch
ifdef COMPILE_USING_WINE
	cd $(TRANS_DEST)/drbd/ && $(MAKE) BUILD_ENV=jt-wine
else
	@echo "Now please run 'make' in the Windows VM."
endif

compile:
	cd $(TRANS_DEST)/drbd/ && $(MAKE) BUILD_ENV=jt-wine

install:
	@echo "This is not a Windows machine. Since we are building a Windows"
	@echo "kernel driver, execute make install on your Windows box (as"
	@echo "Administrator)"

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

# vim: set ts=8 sw=8 noet : 
