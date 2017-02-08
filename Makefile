

EWDK_PATH := ../

EWDK_INC := "$(EWDK_PATH)/ewdk/Program Files/Windows Kits/10/Include"

TRANS_SRC := drbd/
TRANS_DEST := converted-sources/
OV_INC := $(TRANS_DEST)/overrides/

TRANSFORMATIONS := $(sort $(wildcard transform.d/*))
ORIG := $(shell find $(TRANS_SRC) -name "*.[ch]" | grep  -v drbd/drbd-kernel-compat | grep -v drbd_transport_tcp.c)
TRANSFORMED := $(patsubst $(TRANS_SRC)%,$(TRANS_DEST)%,$(ORIG))

export SHELL=bash

all: transform patch msbuild

# can not regenerate those scripts
$(TRANSFORMATIONS): ;

# can not regenerate the originals
$(ORIG): ;

$(TRANSFORMED): $(TRANSFORMATIONS) Makefile

$(TRANS_DEST)% : $(TRANS_SRC)%
	./transform $< $@

transform: $(TRANSFORMED)

patch:
	echo "const char *drbd_buildtag(void){return \"WDRBD: `git describe --tags --always --dirty`\";}" > $(TRANS_DEST)/drbd/drbd_buildtag.c
	cp -a ./Makefile.win $(TRANS_DEST)/drbd/Makefile
	cp -a ./ms-cl.cmd $(TRANS_DEST)/drbd/
	# INCLUDES
	mkdir -p $(OV_INC)/{linux,asm,sys,net,linux-compat,windows,crypto}
	./transform.d/0111-macro-varargs < wdrbd9/generic_compat_stuff.h > $(OV_INC)/generic_compat_stuff.h
	cp ./wdrbd9/drbd_windows.h $(OV_INC)/
	cp ./wdrbd9/windows/wingenl.h $(OV_INC)/
	# replacing files in <drbd>
	cp ./windows/drbd_transport_tcp.c $(TRANS_DEST)/drbd/
	cp ./windows/drbd_polymorph_printk.h $(TRANS_DEST)/drbd/
	# <linux/...>
	for f in ctype.h init.h reboot.h notifier.h workqueue.h kthread.h device.h dynamic_debug.h cpumask.h prefetch.h debugfs.h in.h blkdev.h blkpg.h genhd.h backing-dev.h unistd.h stat.h crc32c.h ratelimit.h mm_inline.h major.h scatterlist.h mutex.h compiler.h memcontrol.h module.h uaccess.h fs.h file.h proc_fs.h errno.h pkt_sched.h net.h tcp.h highmem.h netlink.h genetlink.h slab.h string.h version.h random.h kref.h wait.h version.h vmalloc.h mm.h; do ( cd $(OV_INC) && truncate -s0 linux/$$f;); done
	echo '#include "wsk2.h"' > $(OV_INC)/linux/socket.h
	cp ./wdrbd9/linux-compat/{jiffies.h,seq_file.h,seq_file.c,sched.h,idr.h} $(OV_INC)/linux
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
	for f in stdint.h; do ( cd $(OV_INC) && truncate -s0 $$f;); done
	cp ./wdrbd9/drbd_wrappers.h $(OV_INC)

ifeq ($(shell uname -o),Cygwin)
msbuild:
	cd converted-sources/drbd/ && $(MAKE)
else
msbuild:
	echo "Please run 'make' in the Windows VM."
	exit 1
endif
	

clean:
	test -n "$(TRANS_DEST)" && rm -rf "$(TRANS_DEST)" # Be careful!

# vim: set ts=8 sw=8 noet : 
