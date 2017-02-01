

EWDK_PATH := ../

EWDK_INC := "$(EWDK_PATH)/ewdk/Program Files/Windows Kits/10/Include"

CONV_SRC := drbd/
CONV_DEST := converted-sources/
CONV_SCRIPTS := conversion-scripts/
OV_INC := $(CONV_DEST)/overrides/

ORIG := $(shell find $(CONV_SRC) -name "*.[ch]")
CONVERTED := $(patsubst $(CONV_SRC)%,$(CONV_DEST)%,$(ORIG))
SCRIPTS := $(sort $(wildcard $(CONV_SCRIPTS)/*))

export SHELL=bash

all: transform patch msbuild

# can not regenerate those scritps
$(SCRIPTS): ;

# can not regenerate the originals
$(ORIG): ;

$(CONVERTED): $(SCRIPTS) Makefile

define convert
	set -e ; \
	mkdir -p `dirname $@`; \
	tmp=$@.tmp; \
	cat < $< > $$tmp; \
	for s in $(SCRIPTS); do \
		$$s $$tmp ; \
	done ; \
	mv -v $$tmp $@
endef

$(CONV_DEST)% : $(CONV_SRC)%
	$(call convert)

transform: $(CONVERTED)

patch:
	cd $(CONV_SRC)/drbd && echo 'const char *drbd_buildtag(void){return "WDRBD";}' > drbd_buildtag.c
	cp -a ./Makefile.win $(CONV_DEST)/drbd/Makefile
	cp -a ./ms-cl.cmd $(CONV_DEST)/drbd/
	cp -a data/wdrbd9.vcxproj $(CONV_DEST)/drbd
	# INCLUDES
	mkdir -p $(OV_INC)/{linux,asm,sys,net,linux-compat}
	cp ./wdrbd9/generic_compat_stuff.h $(OV_INC)/
	cp ./wdrbd9/drbd_windows.h $(OV_INC)/
	# <linux/...>
	for f in module.h uaccess.h fs.h file.h proc_fs.h errno.h socket.h pkt_sched.h net.h tcp.h highmem.h netlink.h genetlink.h; do ( cd $(OV_INC) && truncate -s0 linux/$$f;); done
	cp  ./wdrbd9/linux-compat/{jiffies.h,seq_file.h,seq_file.c,sched.h} $(OV_INC)/linux
	cp  ./wdrbd9/linux-compat/Kernel.h $(OV_INC)/linux/kernel.h
	cp  ./wdrbd9/linux-compat/Bitops.h $(OV_INC)/linux/bitops.h
	cp ./wdrbd9/windows/types.h $(OV_INC)/linux/
	# <asm/...>
	for f in kmap_types.h types.h unaligned.h byteorder.h; do ( cd $(OV_INC) && truncate -s0 asm/$$f;); done
	# <net/...>
	for f in genetlink.h; do ( cd $(OV_INC) && truncate -s0 net/$$f;); done
	# <sys/...>
	cp  ./wdrbd9/linux-compat/Wait.h $(OV_INC)/sys/wait.h
	# things they include as linux-compat/...
	for f in list.h spinlock.h hweight.h; do cp ./wdrbd9/linux-compat/$$f $(OV_INC)/linux-compat/; done

ifeq ($(shell uname -o),Cygwin)
msbuild:
	cd converted-sources/drbd/ && $(MAKE)
else
msbuild:
	echo "Please run 'make' in the Windows VM."
	exit 1
endif
	

clean:
	test -n "$(CONV_DEST)" && rm -rf "$(CONV_DEST)" # Be careful!

# vim: set ts=8 sw=8 noet : 
