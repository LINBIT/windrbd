

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
	# INCLUDES
	mkdir -p $(CONV_DEST)/drbd/{linux,asm,sys}
	# <linux/...>
	for f in module.h uaccess.h fs.h file.h proc_fs.h errno.h socket.h pkt_sched.h net.h tcp.h highmem.h netlink.h genetlink.h types.h; do ( cd $(CONV_DEST)/drbd && truncate -s0 linux/$$f;); done
	cp  ./wdrbd9/linux-compat/{jiffies.h,seq_file.h,seq_file.c} $(CONV_DEST)/drbd/linux
	cp  ./wdrbd9/linux-compat/Kernel.h $(CONV_DEST)/drbd/linux/kernel.h
	# <asm/...>
	for f in kmap_types.h types.h unaligned.h; do ( cd $(CONV_DEST)/drbd && truncate -s0 asm/$$f;); done
	# <sys/...>
	cp  ./wdrbd9/linux-compat/Wait.h $(CONV_DEST)/drbd/sys/wait.h
	# things they include as linux-compat/...
	mkdir -p $(CONV_DEST)/drbd/linux-compat
	for f in list.h spinlock.h; do cp ./wdrbd9/linux-compat/$$f $(CONV_DEST)/drbd/linux-compat/; done
	cp ./wdrbd9/windows/* $(CONV_DEST)/drbd/linux-compat/

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
