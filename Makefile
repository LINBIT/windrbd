default: package-in-docker
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

MINGW_INCLUDES=-I$(REACTOS_BUILD)/xdk -I$(REACTOS_ROOT)/ddk -I$(REACTOS_ROOT)/psdk -I$(REACTOS_ROOT)/reactos -I$(REACTOS_ROOT)/ndk

PATCHED_DRBD_SRCDIR = ./converted-sources/drbd
WINDRBD_SRCDIR = ./windrbd/src

DRBD_FILES += $(PATCHED_DRBD_SRCDIR)/drbd_sender.c $(PATCHED_DRBD_SRCDIR)/drbd_receiver.c $(PATCHED_DRBD_SRCDIR)/drbd_req.c $(PATCHED_DRBD_SRCDIR)/drbd_actlog.c
DRBD_FILES += $(PATCHED_DRBD_SRCDIR)/lru_cache.c $(PATCHED_DRBD_SRCDIR)/drbd_main.c $(PATCHED_DRBD_SRCDIR)/drbd_strings.c $(PATCHED_DRBD_SRCDIR)/drbd_nl.c
DRBD_FILES += $(PATCHED_DRBD_SRCDIR)/drbd_interval.c $(PATCHED_DRBD_SRCDIR)/drbd_state.c $(PATCHED_DRBD_SRCDIR)/drbd_kref_debug.c
DRBD_FILES += $(PATCHED_DRBD_SRCDIR)/drbd_nla.c $(PATCHED_DRBD_SRCDIR)/drbd_transport.c $(PATCHED_DRBD_SRCDIR)/drbd_transport_tcp.c $(PATCHED_DRBD_SRCDIR)/kref_debug.c $(PATCHED_DRBD_SRCDIR)/drbd_buildtag.c $(PATCHED_DRBD_SRCDIR)/drbd_bitmap.c $(PATCHED_DRBD_SRCDIR)/drbd_proc.c

WINDRBD_FILES = $(WINDRBD_SRCDIR)/Attr.c $(WINDRBD_SRCDIR)/disp.c $(WINDRBD_SRCDIR)/drbd_windows.c $(WINDRBD_SRCDIR)/hweight.c \
                $(WINDRBD_SRCDIR)/idr.c $(WINDRBD_SRCDIR)/kmalloc_debug.c $(WINDRBD_SRCDIR)/mempool.c $(WINDRBD_SRCDIR)/printk-to-syslog.c \
                $(WINDRBD_SRCDIR)/rbtree.c $(WINDRBD_SRCDIR)/seq_file.c $(WINDRBD_SRCDIR)/slab.c $(WINDRBD_SRCDIR)/util.c $(WINDRBD_SRCDIR)/windrbd_bootdevice.c \
                $(WINDRBD_SRCDIR)/windrbd_device.c $(WINDRBD_SRCDIR)/windrbd_drbd_url_parser.c $(WINDRBD_SRCDIR)/windrbd_module.c \
                $(WINDRBD_SRCDIR)/windrbd_netlink.c $(WINDRBD_SRCDIR)/windrbd_test.c $(WINDRBD_SRCDIR)/windrbd_threads.c \
                $(WINDRBD_SRCDIR)/windrbd_usermodehelper.c $(WINDRBD_SRCDIR)/windrbd_waitqueue.c \
                $(WINDRBD_SRCDIR)/windrbd_winsocket.c $(WINDRBD_SRCDIR)/windrbd_locking.c \
                $(WINDRBD_SRCDIR)/tiktok.c $(WINDRBD_SRCDIR)/partition_table_template.c

OBJS=$(patsubst %.c,%.o,$(DRBD_FILES)) $(patsubst %.c,%.o,$(WINDRBD_FILES)) ./windrbd/windrbd-event-log.coffres ./converted-sources/drbd/resource.coffres

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

windrbd.sys: versioninfo converted-sources $(OBJS) converted-sources/drbd/drbd_buildtag.c
	$(CC) -o windrbd.sys-unsigned $(OBJS) $(LIBS) $(LDFLAGS_FOR_DRIVERS) -g
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
	make -C generate-cat-file clean
	make -C drbd-utils clean

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
