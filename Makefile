# default: package-in-docker
default: orig-drbd
# If you have your dev env set up on the host you can try
# to build without docker container: to set it up the
# contents of the docker-root/Dockerfile might be useful.
# Keep in mind that this requires a modern (2022 or later)
# Linux distribution (with a recent GLIBC) for building
# drbd-utils.

# default: all
# default: package

help:
	@echo "                        WinDRBD 1.2 build help"
	@echo "                        ----------------------"
	@echo
	@echo "Available targets:"
	@echo
	@echo "    pull-docker:        Pull a docker container with all needed"
	@echo "                        build dependencies"
	@echo "    all-in-docker:      build WinDRBD driver and utils in a"
	@echo "                        docker container"
	@echo "    package-in-docker:  build all and create an installable"
	@echo "                        package (self extracting EXE file)"
	@echo "    all:                build WinDRBD driver and utils on the host machine"
	@echo "    windrbd.sys:        build WinDRBD driver"
	@echo "    windrbd.cat:        build WinDRBD security catalog"
	@echo "    drbd-utils:         build usermode utilities for WinDRBD"
	@echo "    clean:              remove all generated files (except converted-sources)"
	@echo "    package:            build all and create installable package (EXE)"
	@echo "    docker:             build docker image with build dependencies"
	@echo "    converted-sources:  apply WinDRBD patches to DRBD"
	@echo "    install:            copy package to Windows hosts and run the installer"
	@echo "                        there (requires CygWin with sshd on target machine)"
	@echo "    orig-drbd:          Compile DRBD from original source (experimental)"
	@echo
	@echo "Variables that control things:"
	@echo
	@echo "    ARCH=[i686|x86_64]  Architecture to build for"
	@echo "    VERSION=myversion   Version string to add to WinDRBD version"
	@echo "    REACTOS=1           Build and package for ReactOS"
	@echo "    NUM_JOBS=j          Use j build jobs in paralell (in-docker targets"
	@echo "    DOCKER_IMAGE=img    Use this docker image for building or generating"
	@echo "    TARGET_IPS=<ips>    Install onto those Windows machines (install target)"
	@echo
	@echo "Examples:"
	@echo
	@echo "        make package-in-docker VERSION=my-windrbd-build"
	@echo "        make package-in-docker VERSION=my-i686-build ARCH=i686"
	@echo "        make package-in-docker VERSION=my-reactos-build ARCH=i686 REACTOS=1"
	@echo
	@echo "If you just want to build WinDRBD with all dependencies in"
	@echo "a docker container, do"
	@echo
	@echo "    make pull-docker && make package-in-docker"
	@echo

ARCH ?= x86_64
# ARCH=i686

TARGET_IPS ?= 10.43.224.4 10.43.224.25

GIT_VERSION=$(shell git describe --tags)
ifdef VERSION
FULL_VERSION=$(GIT_VERSION)-$(VERSION)
else
FULL_VERSION=$(GIT_VERSION)
endif

MINGW_SYSROOT=$(HOME)/.zeranoe/mingw-w64/$(ARCH)
CC=$(MINGW_SYSROOT)/bin/$(ARCH)-w64-mingw32-gcc
RC=$(MINGW_SYSROOT)/bin/$(ARCH)-w64-mingw32-windres
MC=$(MINGW_SYSROOT)/bin/$(ARCH)-w64-mingw32-windmc

HOSTCC ?= gcc

REACTOS_ROOT=windrbd/include/from-reactos
REACTOS_BUILD=windrbd/include/from-reactos/output-$(ARCH)

WINE=/usr/bin/wine

NUM_JOBS ?= $(shell nproc)
MY_UID ?= $(shell id -u)
MY_GID ?= $(shell id -g)

DOCKER_IMAGE ?= windrbd-devenv
# Does not work. /wine is owned by root and we can't
# chown it since we don't know the UID when the docker
# image is built.
# DOCKER_RUN=docker run -u $(MY_UID):$(MY_GID) --rm -v ${PWD}:/windrbd $(DOCKER_IMAGE)
# so run docker as root ...
DOCKER_RUN=docker run --rm -v ${PWD}:/windrbd $(DOCKER_IMAGE)

# Change ownership of all files created by make process to
# the host's UID/GID.
FIXUP_OWNERSHIP=bash -c 'f=`find /windrbd -user root` ; if [ x"$$f" != x ] ; then chown $(MY_UID):$(MY_GID) $$f ; fi'

pull-docker:
	docker pull quay.io/johannesthoma/windrbd-devenv
	docker tag quay.io/johannesthoma/windrbd-devenv windrbd-devenv

# so one can type make with-docker :)
with-docker:
	$(DOCKER_RUN) make -j $(NUM_JOBS) -C windrbd $(WHAT) VERSION=$(VERSION) ARCH=$(ARCH) REACTOS=$(REACTOS)
	$(DOCKER_RUN) $(FIXUP_OWNERSHIP)

all-in-docker:
	$(DOCKER_RUN) make -j $(NUM_JOBS) -C windrbd all VERSION=$(VERSION) ARCH=$(ARCH) REACTOS=$(REACTOS)
	$(DOCKER_RUN) $(FIXUP_OWNERSHIP)

package-in-docker:
	$(DOCKER_RUN) make -j $(NUM_JOBS) -C windrbd package VERSION=$(VERSION) ARCH=$(ARCH) REACTOS=$(REACTOS)
	$(DOCKER_RUN) $(FIXUP_OWNERSHIP)

ifeq ($(ARCH), i686)
DRIVER_ENTRY=_DriverEntry
endif

ifeq ($(ARCH), x86_64)
DRIVER_ENTRY=DriverEntry
endif

# TODO: __MINGW64__ also for 32 bit?
DEFINES=-D WINNT=1 -D KMALLOC_DEBUG=1 -D __KERNEL__=1 -D __BYTE_ORDER=1 -D __LITTLE_ENDIAN=1 -D __LITTLE_ENDIAN_BITFIELD -D COMPAT_HAVE_BOOL_TYPE=1  -D CONFIG_KREF_DEBUG=1 -D __MINGW64__=1

ifdef REACTOS
DEFINES+=-DREACTOS
endif

ifeq ($(ARCH), x86_64)
DEFINES+=-D_WIN64
endif

WINDRBD_INCLUDES=-I"windrbd/include" -I"converted-sources/drbd" -I"converted-sources/drbd/drbd-headers"
# no converted-sources instead drbd-tmp
WINDRBD_NEW_INCLUDES=-I"windrbd/include" -I"drbd-tmp/drbd" -I"drbd-tmp/drbd/drbd-headers" -I"drbd-tmp/drbd/drbd-kernel-compat"
DEVICE_MAPPER_INCLUDES=-I"windrbd/include" -I"linux/drivers/md"

MINGW_INCLUDES=-I$(REACTOS_BUILD)/xdk -I$(REACTOS_ROOT)/ddk -I$(REACTOS_ROOT)/psdk -I$(REACTOS_ROOT)/reactos -I$(REACTOS_ROOT)/ndk

DRBD_SRCDIR=./drbd-tmp/drbd/
PATCHED_DRBD_SRCDIR = ./converted-sources/drbd/

DRBD_SOURCES += drbd_sender.c drbd_receiver.c drbd_req.c drbd_actlog.c
DRBD_SOURCES += lru_cache.c drbd_main.c drbd_strings.c drbd_nl.c
DRBD_SOURCES += drbd_interval.c drbd_state.c drbd_kref_debug.c
DRBD_SOURCES += drbd_nla.c drbd_transport.c drbd_transport_tcp.c kref_debug.c drbd_buildtag.c drbd_bitmap.c drbd_proc.c

ORIG_DRBD_FILES = $(addprefix $(DRBD_SRCDIR), $(DRBD_SOURCES))
# will go away:
DRBD_FILES = $(addprefix $(PATCHED_DRBD_SRCDIR), $(DRBD_SOURCES))

DEVICE_MAPPER_SOURCES=dm.c
DEVICE_MAPPER_FILES = $(addprefix linux/drivers/md/, $(DEVICE_MAPPER_SOURCES))

WINDRBD_SRCDIR = ./windrbd/src/
WINDRBD_SOURCES = Attr.c disp.c drbd_windows.c hweight.c \
                idr.c kmalloc_debug.c mempool.c printk-to-syslog.c \
                rbtree.c seq_file.c slab.c util.c windrbd_bootdevice.c \
                windrbd_device.c windrbd_drbd_url_parser.c windrbd_module.c \
                windrbd_netlink.c windrbd_test.c windrbd_threads.c \
                windrbd_usermodehelper.c windrbd_waitqueue.c \
                windrbd_winsocket.c windrbd_locking.c \
                tiktok.c partition_table_template.c

WINDRBD_FILES = $(addprefix $(WINDRBD_SRCDIR), $(WINDRBD_SOURCES))

ORIG_OBJS=$(patsubst %.c,%.o,$(ORIG_DRBD_FILES)) 
OBJS=$(patsubst %.c,%.o,$(DRBD_FILES)) $(patsubst %.c,%.o,$(WINDRBD_FILES)) ./windrbd/windrbd-event-log.coffres ./converted-sources/drbd/resource.coffres
DEVICE_MAPPER_OBJS=$(patsubst %.c,%.o,$(DEVICE_MAPPER_FILES)) 

LIBS=-lntoskrnl -lhal -lgcc -lntdll -lnetio

CFLAGS_FOR_DRIVERS=-fPIC -fvisibility=hidden -ffunction-sections -fdata-sections -fno-builtin -ffreestanding -fno-stack-protector -mno-stack-arg-probe
LDFLAGS_FOR_DRIVERS=-shared -Wl,--subsystem,native -Wl,--image-base,0x140000000 -Wl,--dynamicbase -Wl,--nxcompat -Wl,--file-alignment,0x200 -Wl,--section-alignment,0x1000 -Wl,--stack,0x100000 -Wl,--gc-sections -Wl,--exclude-all-symbols -Wl,--entry,$(DRIVER_ENTRY) -nostartfiles -nodefaultlibs -nostdlib -Wl,-Map='windrbd.sys.map'

%.coffres: %.rc
	$(RC) -i $< -o $@ -O coff

ifndef REACTOS
OPTIMIZE=-O2
endif

CFLAGS=-g $(OPTIMIZE) -w $(CFLAGS_FOR_DRIVERS) $(DEFINES) $(WINDRBD_INCLUDES) $(MINGW_INCLUDES)

all: windrbd.sys windrbd.cat

windrbd/windrbd-event-log.rc: windrbd/windrbd-event-log.mc
	$(MC) $< -r windrbd -h windrbd/include

windrbd/include/windrbd-event-log.h: windrbd/windrbd-event-log.mc
	$(MC) $< -r windrbd -h windrbd/include

windrbd/src/printk-to-syslog.o: windrbd/include/windrbd-event-log.h

versioninfo:
	./versioninfo.sh converted-sources $(VERSION)

# converted-sources should not be .PHONY
# generate it on the first build then leave it
# alone (until either renamed or removed)

# TODO: still fails to depend on drbd_buildtag when
# -j is larger than 1...
.PHONY: windrbd.sys
.PHONY: windrbd.cat
.PHONY: converted-sources/drbd/drbd_buildtag.c
.PHONY: converted-sources/drbd/drbd_buildtag.obj

converted-sources/drbd/drbd_buildtag.c: versioninfo

orig-drbd: $(ORIG_DRBD_FILES) $(ORIG_OBJS)

device-mapper: $(DEVICE_MAPPER_OBJS)

CFLAGS=-g $(OPTIMIZE) $(CFLAGS_FOR_DRIVERS) $(DEFINES) $(WINDRBD_NEW_INCLUDES) $(MINGW_INCLUDES)

windrbd.sys: versioninfo $(ORIG_DRBD_FILES) $(ORIG_OBJS)
	$(CC) -o windrbd.sys-unsigned $(ORIG_OBJS) $(LIBS) $(LDFLAGS_FOR_DRIVERS) -g
	osslsigncode sign -key crypto/linbit-2019.pvk -certs crypto/linbit-2019.spc windrbd.sys-unsigned windrbd.sys-signed
	mv windrbd.sys-signed windrbd.sys
	rm -f windrbd.sys-unsigned

windrbd.cat: windrbd.sys
# build the cat file generator. It is not yet in any Linux distros ...
# if this fails then you probably forgot to clone with --recursive.
# You may want to do something like git submodule update or so..
	make -C generate-cat-file CC=$(HOSTCC)
	generate-cat-file/gencat.sh -o windrbd.cat-unsigned -h windrbd windrbd.inf windrbd.sys

	rm -f windrbd.cat
# TODO: This needs a 'modern' osslsigncode (that from Ubuntu 18.04 and also
# from Ubuntu 20.04 is too old - you probably have to build it yourself)
	osslsigncode sign -key crypto/linbit-2019.pvk -certs crypto/linbit-2019.spc windrbd.cat-unsigned windrbd.cat
#	rm -f windrbd.cat-unsigned

.PHONY: drbd-utils

drbd-utils:
	cd drbd-utils && ./autogen.sh
	cd drbd-utils && ./configure --without-83support --without-84support --without-drbdmon --with-windrbd --without-manual --prefix=/cygdrive/c/windrbd/usr --localstatedir=/cygdrive/c/windrbd/var --sysconfdir=/cygdrive/c/windrbd/etc --host=$(ARCH)-pc-cygwin
	make -C drbd-utils -j $(NUM_JOBS)

clean:
	rm -f $(OBJS)
	rm -f windrbd.sys windrbd.sys.map windrbd.cat windrbd.inf
	rm -f windrbd/msg00002.bin windrbd/include/windrbd-event-log.h windrbd/windrbd-event-log.rc
	rm -f windrbd.cat-unsigned windrbd.sys-unsigned windrbd.sys-signed
	rm -rf drbd-tmp
	make -C generate-cat-file clean
	make -C drbd-utils clean

clean-converted-sources:
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

ifdef REACTOS
EXTRA_ISCC_DEFINES=/DReactos=1
endif

package: all drbd-utils
	( cd inno-setup && $(WINE) "C:\Program Files (x86)\Inno Setup 5\iscc.exe" windrbd.iss /DWindrbdSource=.. /DWindrbdUtilsSource=..\\drbd-utils /DWindrbdDriverDirectory=$(DRIVER_DIR) /DArch=$(ARCH) $(EXTRA_ISCC_DEFINES))

docker:
	docker build --pull=true --no-cache=true -t $(DOCKER_IMAGE) docker-root

docker-fc37:
	docker build --pull=true --no-cache=true -t $(DOCKER_IMAGE)-fc37 -f docker-root/Dockerfile-fc37 docker-root

docker-wine64:
	docker build --pull=true --no-cache=true -t $(DOCKER_IMAGE)-wine64 -f docker-root/Dockerfile-wine64 docker-root

docker-cygwin:
	docker build --pull=true --no-cache=true -t $(DOCKER_IMAGE)-cygwin -f docker-root/Dockerfile-cygwin docker-root

install:
	inno-setup/deploy.sh inno-setup/install-$(FULL_VERSION).exe $(TARGET_IPS)

# From original Linux Makefile: this will go away (hopefully
# soon) when we switch to a git branch on DRBD upstream +
# some cocci's.

TRANS_SRC := drbd/
TRANS_DEST := converted-sources/
WIN4LIN := windrbd/

TRANSFORMATIONS := $(sort $(wildcard transform.d/*))
ORIG := $(shell find $(TRANS_SRC) -name "*.[ch]" | egrep -v 'drbd/drbd-kernel-compat|drbd_transport_template.c|drbd_buildtag.c|compat.h|drbd_polymorph_printk.h')
TRANSFORMED := $(patsubst $(TRANS_SRC)%,$(TRANS_DEST)%,$(ORIG))

export SHELL=bash
export V=1

# can not regenerate those scripts
$(TRANSFORMATIONS): ;

# can not regenerate the originals
$(ORIG): ;

$(TRANSFORMED): $(TRANSFORMATIONS) transform

$(TRANS_DEST)% : $(TRANS_SRC)%
	@./transform $< $@

$(TRANS_DEST).generated: $(ORIG)
	echo $(TRANSFORMED) > $(TRANS_DEST).generated

trans: $(TRANSFORMED) $(TRANS_DEST).generated

converted-sources: trans

NEW_TRANSFORMATIONS := $(sort $(wildcard cocci/*))

DRBD_HEADERS := $(shell find drbd -name "*.h")
DRBD_TMP_HEADERS := $(patsubst drbd%,drbd-tmp%,$(DRBD_HEADERS))

drbd-tmp/%.h: drbd/%.h
	if [ -e drbd/drbd/compat.h ] ; then echo "Stale compat.h in DRBD sources. Do not run make in the drbd directory." ; exit 1 ; fi
	mkdir -p $(shell dirname $@) && cp $< $@
	for c in $(NEW_TRANSFORMATIONS) ; do spatch --sp-file $$c $@ --in-place ; done

# TODO: should we depend on DRBD_TMP_HEADERS here? This makes
# make copy all the headers over to drbd-tmp and patch them..
# Alternative is to use -MG (and not explicitly depend).
# from make documentation, automatic prerequisites
%.d: %.c $(DRBD_TMP_HEADERS)
	set -e; rm -f $@; \
	$(CC) -MM -MT $(patsubst %.c,%.o,$<)  $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

all-dep := $(filter-out drbd_buildtag.d,$(ORIG_OBJS:%.o=%.d))

ifeq ($(MAKECMDGOALS),$(filter-out clean,$(MAKECMDGOALS)))
-include $(all-dep)
endif

drbd-tmp/%.c: drbd/%.c
	if [ -e drbd/drbd/compat.h ] ; then echo "Stale compat.h in DRBD sources. Do not run make in the drbd directory." ; exit 1 ; fi
	mkdir -p drbd-tmp/drbd &&  cp $< $@
	for c in $(NEW_TRANSFORMATIONS) ; do spatch --sp-file $$c $@ --in-place ; done
