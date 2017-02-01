

EWDK_PATH := ../

EWDK_INC := "$(EWDK_PATH)/ewdk/Program Files/Windows Kits/10/Include"

CONV_SRC := $(PWD)/drbd/
CONV_DEST := $(PWD)/converted-sources/
OV_INC := $(CONV_DEST)/overrides/
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
	mkdir -p $(OV_INC)/{linux,asm,sys,linux-compat}
	cp ./wdrbd9/generic_compat_stuff.h $(OV_INC)/
	# <linux/...>
	for f in module.h uaccess.h fs.h file.h proc_fs.h errno.h socket.h pkt_sched.h net.h tcp.h highmem.h netlink.h genetlink.h; do ( cd $(OV_INC) && truncate -s0 linux/$$f;); done
	cp  ./wdrbd9/linux-compat/{jiffies.h,seq_file.h,seq_file.c,sched.h} $(OV_INC)/linux
	cp  ./wdrbd9/linux-compat/Kernel.h $(OV_INC)/linux/kernel.h
	cp  ./wdrbd9/linux-compat/Bitops.h $(OV_INC)/linux/bitops.h
	cp ./wdrbd9/windows/types.h $(OV_INC)/linux/
	# <asm/...>
	for f in kmap_types.h types.h unaligned.h byteorder.h; do ( cd $(OV_INC) && truncate -s0 asm/$$f;); done
	# <sys/...>
	cp  ./wdrbd9/linux-compat/Wait.h $(OV_INC)/sys/wait.h
	# things they include as linux-compat/...
	for f in list.h spinlock.h; do cp ./wdrbd9/linux-compat/$$f $(OV_INC)/linux-compat/; done

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
