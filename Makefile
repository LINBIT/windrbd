

EWDK_PATH := ../

EWDK_INC := "$(EWDK_PATH)/ewdk/Program Files/Windows Kits/10/Include"

TRANS_SRC := drbd/
TRANS_DEST := converted-sources/
OV_INC := $(TRANS_DEST)/overrides/

TRANSFORMATIONS := $(sort $(wildcard transform.d/*))
ORIG := $(shell find $(TRANS_SRC) -name "*.[ch]" | egrep -v 'drbd/drbd-kernel-compat|drbd_transport_tcp.c|drbd_polymorph_printk.h|drbd_buildtag.c|drbd_transport_template.c')
TRANSFORMED := $(patsubst $(TRANS_SRC)%,$(TRANS_DEST)%,$(ORIG))

export SHELL=bash

all: trans patch msbuild

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
	# INCLUDES
	mkdir -p $(OV_INC)/{linux,asm,sys,net,linux-compat,windows,crypto}
	./transform.d/211-macro-varargs < wdrbd9/generic_compat_stuff.h > $(OV_INC)/generic_compat_stuff.h
	$(CP) ./wdrbd9/drbd_windows.h $(OV_INC)/
	$(CP) ./wdrbd9/windows/wingenl.h $(OV_INC)/
	# replacing files in <drbd>
	$(CP) ./windows/drbd_transport_tcp.c $(TRANS_DEST)/drbd/
	$(CP) ./windows/drbd_polymorph_printk.h $(TRANS_DEST)/drbd/
	$(CP) ./windows/drbd_proc.c $(TRANS_DEST)/drbd/
	# <linux/...>
	for f in swab.h security.h ctype.h init.h reboot.h notifier.h workqueue.h kthread.h device.h dynamic_debug.h cpumask.h prefetch.h debugfs.h in.h blkpg.h genhd.h backing-dev.h unistd.h stat.h crc32c.h ratelimit.h mm_inline.h major.h scatterlist.h mutex.h compiler.h memcontrol.h module.h uaccess.h fs.h file.h proc_fs.h errno.h pkt_sched.h net.h tcp.h highmem.h netlink.h genetlink.h string.h version.h random.h kref.h wait.h version.h vmalloc.h mm.h moduleparam.h; do ( cd $(OV_INC) && truncate -s0 linux/$$f;); done
	echo '#include "wsk2.h"' > $(OV_INC)/linux/socket.h
	$(CP) ./wdrbd9/linux-compat/{jiffies.h,seq_file.h,sched.h,idr.h,stddef.h} $(OV_INC)/linux
	$(CP) ./wdrbd9/linux-compat/Kernel.h $(OV_INC)/linux/kernel.h
	$(CP) ./wdrbd9/linux-compat/Bitops.h $(OV_INC)/linux/bitops.h
	$(CP) ./wdrbd9/windows/types.h $(OV_INC)/linux/
	$(CP) ./wdrbd9/linux-compat/list.h $(OV_INC)/linux/
	$(CP) ./wdrbd9/linux-compat/rbtree.h $(OV_INC)/linux/
	$(CP) ./wdrbd9/linux-compat/spinlock.h $(OV_INC)/linux
	$(CP) ./wdrbd9/linux-compat/slab.h $(OV_INC)/linux
	$(CP) ./wdrbd9/linux-compat/blkdev.h $(OV_INC)/linux
	$(CP) ./wdrbd9/linux-compat/bio.h $(OV_INC)/linux
	$(CP) ./wdrbd9/linux-compat/mempool.h $(OV_INC)/linux
	$(CP) ./wdrbd9/linux-compat/drbd_endian.h $(OV_INC)/linux
	$(CP) ./wdrbd9/linux-compat/hweight.h $(OV_INC)/linux
	$(CP) ./windows/stringify.h $(OV_INC)/linux
	# <asm/...>
	for f in kmap_types.h types.h unaligned.h byteorder.h; do ( cd $(OV_INC) && truncate -s0 asm/$$f;); done
	# <net/...>
	for f in genetlink.h ipv6.h netlink.h sock.h; do ( cd $(OV_INC) && truncate -s0 net/$$f;); done
	# <crypto/...>
	mkdir -p $(OV_INC)/crypto
	$(CP) ./wdrbd9/crypto_hash.h $(OV_INC)/crypto/hash.h
	# <sys/...>
	$(CP) ./wdrbd9/linux-compat/Wait.h $(OV_INC)/sys/wait.h
	# <windows/>
	for f in ioctl.h drbd.h; do $(CP) ./wdrbd9/windows/$$f $(OV_INC)/windows/; done
	# standard
	for f in drbd_wingenl.h mvolmsg.h disp.h mvolse.h send_buf.h wsk2.h; do $(CP) ./wdrbd9/$$f $(OV_INC)/; done
	# additional toplevel
	for f in stdint.h; do ( cd $(OV_INC) && truncate -s0 $$f;); done
	$(CP) ./wdrbd9/loglink.h ./wdrbd9/drbd_wrappers.h ./wdrbd9/proto.h $(OV_INC)
	# To compile test the .c file, before we sanitize the repository layout....
	$(CP) ./wdrbd9/data.c ./wdrbd9/send_buf.c ./wdrbd9/thread.c ./wdrbd9/loglink.c ./wdrbd9/ops.c ./wdrbd9/util.c ./wdrbd9/sub.c ./wdrbd9/wsk2.c wdrbd9/disp.c ./wdrbd9/slab.c ./wdrbd9/mempool.c ./wdrbd9/drbd_windows.c ./windows/printk-to-syslog.c $(TRANS_DEST)/drbd/
	$(CP) ./wdrbd9/linux-compat/netlink.c $(TRANS_DEST)/drbd/netlink.c_inc
	$(CP) ./wdrbd9/linux-compat/rbtree.c ./wdrbd9/linux-compat/hweight.c ./wdrbd9/linux-compat/Attr.c ./wdrbd9/linux-compat/seq_file.c ./wdrbd9/linux-compat/idr.c $(TRANS_DEST)/drbd/

ifeq ($(shell uname -o),Cygwin)
msbuild: patch
	cd converted-sources/drbd/ && $(MAKE)
else
msbuild: patch
	echo "Please run 'make' in the Windows VM."
	exit 1
endif
	

clean:
	if test -n $(TRANS_DEST); then \
		rm -f $(shell cat $(TRANS_DEST).generated) $(TRANS_DEST).generated; \
		find $(TRANS_DEST) -name "*.tmp.bak" -delete; \
		find $(TRANS_DEST) -name "*.pdb" -delete; \
		find $(TRANS_DEST) -name "*.obj" -delete; \
		find $(TRANS_DEST) -name "*.orig" -delete; \
		find $(TRANS_DEST) -name "*.tmpe" -delete; \
	fi

# vim: set ts=8 sw=8 noet : 
