

EWDK_PATH := ../

EWDK_INC := "$(EWDK_PATH)/ewdk/Program Files/Windows Kits/10/Include"

CONV_SRC := $(PWD)/drbd/
CONV_DEST := $(PWD)/converted-sources/
CONV_SCRIPTS := $(PWD)/conversion-scripts/

SOURCE_FILES := *.[ch]

export SHELL=bash


all: copy change msbuild

copy:
	mkdir -p $(CONV_DEST)/
	cp -ra $(CONV_SRC)/* $(CONV_DEST)
	cd $(CONV_SRC)/drbd && echo 'const char *drbd_buildtag(void){return "WDRBD";}' > drbd_buildtag.c
	cp -a ./Makefile.win $(CONV_DEST)/drbd/Makefile
	cp -a ./ms-cl.cmd $(CONV_DEST)/drbd/
	cp -a data/wdrbd9.vcxproj $(CONV_DEST)/drbd

change:
	# These scripts must be callable multiple times
	set -e ; for cmd in $(CONV_SCRIPTS)/* ; do ( cd $(CONV_DEST)/drbd && if test -x "$$cmd" ; then echo "## $$cmd ##" && "$$cmd" ./$(SOURCE_FILES) ; fi ) || echo "ERROR $$?" ; done
	mkdir -p $(CONV_DEST)/drbd/{linux,asm}
	for f in module.h uaccess.h fs.h file.h proc_fs.h seq_file.h; do ( cd $(CONV_DEST)/drbd && touch linux/$$f;); done
	for f in kmap_types.h types.h unaligned.h; do ( cd $(CONV_DEST)/drbd && touch asm/$$f;); done

ifeq ($(shell uname -o),Cygwin)
msbuild:
	cd converted-sources/drbd/ && $(MAKE)
else
msbuild:
	echo "Please run 'make' in the Windows VM."
	exit 1
endif
	

clean:
	test -n "$(CONV_DEST)" && test -n "$(SOURCE_FILES)" && rm -f "$(CONV_DEST)/$(SOURCE_FILES)" # Be careful

# vim: set ts=8 sw=8 noet : 
