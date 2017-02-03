

EWDK_PATH := ../

EWDK_INC := "$(EWDK_PATH)/ewdk/Program Files/Windows Kits/10/Include"

CONV_SRC := drbd/
CONV_DEST := converted-sources/
CONV_SCRIPTS := transformation-scripts/
OV_INC := $(CONV_DEST)/overrides/

ORIG := $(shell find $(CONV_SRC) -name "*.[ch]" | grep  -v drbd/drbd-kernel-compat)
CONVERTED := $(patsubst $(CONV_SRC)%,$(CONV_DEST)%,$(ORIG))
SCRIPTS := $(sort $(wildcard $(CONV_SCRIPTS)/*))

export SHELL=bash

all: transform patch msbuild

# can not regenerate those scripts
$(SCRIPTS): ;

# can not regenerate the originals
$(ORIG): ;

$(CONVERTED): $(SCRIPTS) Makefile

define convert
	@set -e ; \
	mkdir -p `dirname $@`; \
	tmp=$@.tmp; \
	cat < $< > $$tmp; \
	for s in $(SCRIPTS); do \
		printf "   CONVERSION: %-40s < %s" "$$s" "$@" ; \
		if test -x $$s ; then $$s $$tmp ; fi ;\
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
	# INCLUDES
	mkdir -p $(OV_INC)/{linux,asm,sys,net,linux-compat,windows,crypto}
	cp ./wdrbd9/generic_compat_stuff.h $(OV_INC)/
	cp ./wdrbd9/drbd_windows.h $(OV_INC)/
	cp ./wdrbd9/windows/wingenl.h $(OV_INC)/
	# replacing files in <drbd>
	cp ./windows/drbd_transport_tcp.c $(CONV_DEST)/drbd/
	cp ./windows/drbd_polymorph_printk.h $(CONV_DEST)/drbd/
	# <linux/...>
	for f in ctype.h init.h reboot.h notifier.h workqueue.h kthread.h device.h dynamic_debug.h cpumask.h idr.h prefetch.h debugfs.h in.h blkdev.h blkpg.h genhd.h backing-dev.h unistd.h stat.h crc32c.h ratelimit.h mm_inline.h major.h scatterlist.h mutex.h compiler.h memcontrol.h module.h uaccess.h fs.h file.h proc_fs.h errno.h pkt_sched.h net.h tcp.h highmem.h netlink.h genetlink.h slab.h string.h version.h random.h kref.h wait.h version.h vmalloc.h mm.h; do ( cd $(OV_INC) && truncate -s0 linux/$$f;); done
	echo '#include "wsk2.h"' > $(OV_INC)/linux/socket.h
	cp ./wdrbd9/linux-compat/{jiffies.h,seq_file.h,seq_file.c,sched.h} $(OV_INC)/linux
	cp ./wdrbd9/linux-compat/Kernel.h $(OV_INC)/linux/kernel.h
	cp ./wdrbd9/linux-compat/Bitops.h $(OV_INC)/linux/bitops.h
	cp ./wdrbd9/windows/types.h $(OV_INC)/linux/
	cp ./wdrbd9/linux-compat/list.h $(OV_INC)/linux/
	cp ./wdrbd9/linux-compat/rbtree.* $(OV_INC)/linux/
	cp ./wdrbd9/linux-compat/spinlock.h $(OV_INC)/linux
	cp ./wdrbd9/drbd_wingenl.h $(OV_INC)/
	# <asm/...>
	for f in kmap_types.h types.h unaligned.h byteorder.h; do ( cd $(OV_INC) && truncate -s0 asm/$$f;); done
	# <net/...>
	for f in genetlink.h ipv6.h netlink.h sock.h; do ( cd $(OV_INC) && truncate -s0 net/$$f;); done
	# <crypto/...>
	for f in hash.h; do ( cd $(OV_INC) && truncate -s0 crypto/$$f;); done
	# <sys/...>
	cp ./wdrbd9/linux-compat/Wait.h $(OV_INC)/sys/wait.h
	# things they include as linux-compat/...
	for f in list.h spinlock.h hweight.h drbd_endian.h; do cp ./wdrbd9/linux-compat/$$f $(OV_INC)/linux-compat/; done
	# <windows/>
	for f in types.h ioctl.h drbd.h; do cp ./wdrbd9/windows/$$f $(OV_INC)/windows/; done
	# standard
	for f in mvolmsg.h disp.h mvolse.h send_buf.h wsk2.h; do cp ./wdrbd9/$$f $(OV_INC)/; done
	# additional toplevel
	for f in drbd_wrappers.h stdint.h; do ( cd $(OV_INC) && truncate -s0 $$f;); done


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
