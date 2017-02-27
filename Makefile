

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
	# To compile test the .c file, before we sanitize the repository layout....
	$(CP) ./wdrbd9/data.c ./wdrbd9/send_buf.c ./wdrbd9/thread.c ./wdrbd9/loglink.c ./wdrbd9/ops.c ./wdrbd9/util.c ./wdrbd9/sub.c ./wdrbd9/wsk2.c wdrbd9/disp.c ./wdrbd9/slab.c ./wdrbd9/mempool.c ./wdrbd9/drbd_windows.c ./windows/printk-to-syslog.c $(TRANS_DEST)/drbd/
	$(CP) ./windows/drbd_polymorph_printk.h $(TRANS_DEST)/drbd/
	$(CP) ./windows/drbd_proc.c $(TRANS_DEST)/drbd/
	$(CP) ./windows/drbd_transport_tcp.c $(TRANS_DEST)/drbd/
	$(CP) ./wdrbd9/linux-compat/netlink.c $(TRANS_DEST)/drbd/netlink.c_inc
	$(CP) ./wdrbd9/linux-compat/rbtree.c ./wdrbd9/linux-compat/hweight.c ./wdrbd9/linux-compat/Attr.c ./wdrbd9/linux-compat/seq_file.c ./wdrbd9/linux-compat/idr.c $(TRANS_DEST)/drbd/

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
		find $(TRANS_DEST) -name "*.tmp.bak" -delete; \
		find $(TRANS_DEST) -name "*.pdb" -delete; \
		find $(TRANS_DEST) -name "*.obj" -delete; \
		find $(TRANS_DEST) -name "*.orig" -delete; \
		find $(TRANS_DEST) -name "*.tmpe" -delete; \
	fi

# vim: set ts=8 sw=8 noet : 
