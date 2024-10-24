DEFAULT ?= package-in-docker

default: $(DEFAULT)

# default: windrbd.sys
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
	@echo "    clean:              remove all generated files"
	@echo "    package:            build all and create installable package (EXE)"
	@echo "    docker:             build docker image with build dependencies"
	@echo "    install:            copy package to Windows hosts and run the installer"
	@echo "                        there (requires CygWin with sshd on target machine)"
	@echo
	@echo "Variables that control things:"
	@echo
	@echo "    ARCH=[i686|x86_64]  Architecture to build for"
	@echo "    VERSION=myversion   Version string to add to WinDRBD version"
	@echo "    REACTOS=1           Build and package for ReactOS"
	@echo "    NUM_JOBS=j          Use j build jobs in paralell (in-docker targets"
	@echo "    DOCKER=docker-cmd   Use this docker command (example: make DOCKER=podman)"
	@echo "    DOCKER_IMAGE=img    Use this docker image for building or generating"
	@echo "    TARGET_IPS=<ips>    Install onto those Windows machines (install target)"
	@echo "    V=1                 If set display command line, else pretty print (default)"
	@echo "    DRIVER_DIR=dir      Take windrbd.sys/cat/inf from this directory"
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

export ARCH ?= x86_64
# ARCH=i686

TARGET_IPS ?= 10.43.224.4 10.43.224.25

export DRBD ?= drbd-9.0
DRBDTMP ?= $(DRBD)-tmp

export REACTOS

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

DOCKER ?= docker
DOCKER_IMAGE ?= windrbd-devenv
# Does not work. /wine is owned by root and we can't
# chown it since we don't know the UID when the docker
# image is built.
# DOCKER_RUN=docker run -u $(MY_UID):$(MY_GID) --rm -v ${PWD}:/windrbd $(DOCKER_IMAGE)
# so run docker as root ...
# Add environment variables to pass to docker here:
DOCKER_RUN=$(DOCKER) run --rm -v ${PWD}:/windrbd -e VERSION=$(VERSION) -e ARCH=$(ARCH) -e REACTOS=$(REACTOS) -e PAGE_KREF_DEBUG=$(PAGE_KREF_DEBUG) -e KREF_DEBUG=$(KREF_DEBUG) -e V=$(V) -e DRBD=$(DRBD) -e DRBDTMP=$(DRBDTMP) -e DRIVER_DIR=$(DRIVER_DIR) $(DOCKER_IMAGE)

# Change ownership of all files created by make process to
# the host's UID/GID.
FIXUP_OWNERSHIP=bash -c 'f=`find /windrbd -user root` ; if [ x"$$f" != x ] ; then chown $(MY_UID):$(MY_GID) $$f ; fi'

export VERSION:=$(VERSION)

# Very simple pretty printer:
ifeq ($(V),1)
run=$1
else
run=@echo $2\\t$3 ; $1
endif

# TODO: use export to pass vars to docker
# KREF_DEBUG := $(KREF_DEBUG)
# export KREF_DEBUG

pull-docker:
	$(DOCKER) pull quay.io/johannesthoma/windrbd-devenv
	$(DOCKER) tag quay.io/johannesthoma/windrbd-devenv windrbd-devenv

# so one can type make with-docker :)
with-docker:
	$(call run,$(DOCKER_RUN) make -j $(NUM_JOBS) -C windrbd $(WHAT),DOCKER,$(DOCKER_IMAGE))
	$(call run,$(DOCKER_RUN) $(FIXUP_OWNERSHIP),DOCKER,$(DOCKER_IMAGE))

all-in-docker:
	$(call run,$(DOCKER_RUN) make -j $(NUM_JOBS) -C windrbd all,DOCKER,$(DOCKER_IMAGE))
	$(call run,$(DOCKER_RUN) $(FIXUP_OWNERSHIP),DOCKER,$(DOCKER_IMAGE))

package-in-docker:
	$(call run,$(DOCKER_RUN) make -j $(NUM_JOBS) -C windrbd package,DOCKER,$(DOCKER_IMAGE))
	$(call run,$(DOCKER_RUN) $(FIXUP_OWNERSHIP),DOCKER,$(DOCKER_IMAGE))

ifeq ($(ARCH), i686)
DRIVER_ENTRY=_DriverEntry
endif

ifeq ($(ARCH), x86_64)
DRIVER_ENTRY=DriverEntry
endif

DEFINES=-D WINNT=1 -D KMALLOC_DEBUG=1 -D __KERNEL__=1 -D __BYTE_ORDER=1 -D __LITTLE_ENDIAN=1 -D __LITTLE_ENDIAN_BITFIELD -D COMPAT_HAVE_BOOL_TYPE=1  -D CONFIG_KREF_DEBUG=1 -DKBUILD_MODNAME='"drbd"' -D CONFIG_WINDOWS=1

# there are 2 different kref debugs: on from DRBD (CONFIG_KREF_DEBUG)
# and one that printk's every kref change (KREF_DEBUG)
# the latter can be enabled with make KREF_DEBUG=1
#
ifdef KREF_DEBUG
DEFINES+=-DKREF_DEBUG=1
endif

ifdef PAGE_KREF_DEBUG
DEFINES+=-DPAGE_KREF_DEBUG=1
endif

ifdef REACTOS
DEFINES+=-DREACTOS
endif

ifeq ($(DRBD),drbd-9.1)
DEFINES+=-DDRBD_9_1=1
endif

DEFINES+=-DBLKDEV_ISSUE_ZEROOUT_EXPORTED=1

ifeq ($(ARCH), x86_64)
DEFINES+=-D_WIN64 -DCONFIG_64BIT -D__x86_64
endif

ifeq ($(ARCH), i686)
DEFINES+=-DCONFIG_32BIT
endif

WINDRBD_INCLUDES=-I"windrbd/include" -I"$(DRBDTMP)/drbd" -I"$(DRBDTMP)/drbd/drbd-headers" -I"$(DRBDTMP)/drbd/drbd-kernel-compat"
MINGW_INCLUDES=-I$(REACTOS_BUILD)/xdk -I$(REACTOS_ROOT)/ddk -I$(REACTOS_ROOT)/psdk -I$(REACTOS_ROOT)/reactos -I$(REACTOS_ROOT)/ndk -I$(REACTOS_ROOT)/crt -nostdinc -I$(REACTOS_ROOT)/lib/pseh/include

DRBD_TMPSRCDIR=$(DRBDTMP)/drbd/

DRBD_SOURCES += drbd_sender.c drbd_receiver.c drbd_req.c drbd_actlog.c
DRBD_SOURCES += drbd_main.c drbd-headers/drbd_strings.c drbd_nl.c
DRBD_SOURCES += drbd_interval.c drbd_state.c drbd_kref_debug.c
DRBD_SOURCES += drbd_nla.c drbd_transport.c drbd_transport_tcp.c kref_debug.c drbd_buildtag.c drbd_bitmap.c drbd_proc.c

ifeq ($(DRBD),drbd-9.0)
DRBD_SOURCES += lru_cache.c
else
DRBD_SOURCES += drbd-kernel-compat/lru_cache.c
endif

TMP_DRBD_FILES = $(addprefix $(DRBD_TMPSRCDIR), $(DRBD_SOURCES))

WINDRBD_SRCDIR = ./windrbd/src/
WINDRBD_SOURCES = Attr.c disp.c drbd_windows.c hweight.c \
                idr.c kmalloc_debug.c mempool.c printk-to-syslog.c \
                seq_file.c slab.c util.c windrbd_bootdevice.c \
                windrbd_device.c windrbd_drbd_url_parser.c windrbd_module.c \
                windrbd_netlink.c windrbd_test.c windrbd_threads.c \
                windrbd_usermodehelper.c windrbd_waitqueue.c \
                windrbd_winsocket.c windrbd_locking.c \
                tiktok.c partition_table_template.c \
                windrbd_serial.c

WINDRBD_FILES = $(addprefix $(WINDRBD_SRCDIR), $(WINDRBD_SOURCES))

LINUX_SRCDIR = ./windrbd/src/from-linux/
# TODO: lib/vsprintf.c does not compile, use the Windows counterpart ...
LINUX_SOURCES = lib/kstrtox.c mm/util.c lib/kasprintf.c block/genhd.c block/blk-settings.c kernel/time/timeconv.c kernel/time/time.c lib/rbtree.c lib/string.c
# LINUX_SOURCES = lib/kstrtox.c mm/util.c
LINUX_FILES = $(addprefix $(LINUX_SRCDIR), $(LINUX_SOURCES))

ifeq ($(ARCH), i686)
SEH_OBJS1 = i386/pseh3_i386.o i386/seh_prolog.o i386/seh.o i386/pseh3.o i386/framebased-gcchack-asm.o i386/framebased-gcchack.o
endif

SEH_SRCDIR = windrbd/include/from-reactos/lib/pseh/
SEH_OBJS = $(addprefix $(SEH_SRCDIR), $(SEH_OBJS1))

OBJS=$(patsubst %.c,%.o,$(TMP_DRBD_FILES)) $(patsubst %.c,%.o,$(WINDRBD_FILES)) $(patsubst %.c,%.o,$(LINUX_FILES)) $(SEH_OBJS)
# OBJS=$(patsubst %.c,%.o,$(TMP_DRBD_FILES))

COFFRES=./windrbd/windrbd-event-log.coffres $(DRBDTMP)/drbd/resource.coffres

LIBS=-lntoskrnl -lhal -lgcc -lntdll -lnetio

SUPPRESSED_WARNINGS=-Wno-array-bounds -Wno-address-of-packed-member
CFLAGS_FOR_DRIVERS=-fPIC -fvisibility=hidden -ffunction-sections -fdata-sections -fno-builtin -ffreestanding -fno-stack-protector -mno-stack-arg-probe -fno-strict-aliasing -fno-set-stack-executable
LDFLAGS_FOR_DRIVERS=-shared -Wl,--subsystem,native -Wl,--image-base,0x140000000 -Wl,--dynamicbase -Wl,--nxcompat -Wl,--file-alignment,0x200 -Wl,--section-alignment,0x1000 -Wl,--stack,0x100000 -Wl,--gc-sections -Wl,--exclude-all-symbols -Wl,--entry,$(DRIVER_ENTRY) -nostartfiles -nodefaultlibs -nostdlib -Wl,-Map='windrbd.sys.map'

SEH_INCLUDES=-I$(REACTOS_ROOT)/crt -I$(REACTOS_ROOT)/lib/pseh/include/pseh -I$(REACTOS_ROOT)/asm

CFLAGS_FOR_SEH=-DDBG=1 -DDLL_EXPORT_VERSION=0x502 -DMINGW_HAS_SECURE_API=1 -DUSE_COMPILER_EXCEPTIONS -DWINVER=0x502 -D_CRT_NON_CONFORMING_SWPRINTFS -D_GLIBCXX_HAVE_BROKEN_VSWPRINTF -D_M_IX86 -D_NEW_DELETE_OPERATORS_ -D_SEH_ENABLE_TRACE -D_SETUPAPI_VER=0x502 -D_USE_32BIT_TIME_T -D_WIN32_IE=0x600 -D_WIN32_WINDOWS=0x502 -D_WIN32_WINNT=0x502 -D_X86_ -D__REACTOS__ -D__RELFILE__="&__FILE__[__FILE__[0] == '.' ? 3 : 31]" -D__i386__ -Di386  -pipe -fms-extensions -fno-strict-aliasing -fno-common -mlong-double-64 -nostdinc -fno-aggressive-loop-optimizations -Wold-style-declaration -gdwarf-2 -ggdb -march=pentium -mtune=generic -Werror -Wall -Wpointer-arith -Wno-char-subscripts -Wno-multichar -Wno-unused-value -Wno-unused-const-variable -Wno-unused-local-typedefs -Wno-deprecated -Wno-unused-result -Wno-maybe-uninitialized -O1 -fno-optimize-sibling-calls -fno-omit-frame-pointer -mstackrealign -mpreferred-stack-boundary=3 -fno-set-stack-executable -std=gnu99 $(SEH_INCLUDES) $(MINGW_INCLUDES)

ASM_CFLAGS_FOR_SEH=-x assembler-with-cpp -pipe -fms-extensions -fno-strict-aliasing -fno-common -mlong-double-64 -nostdinc -fno-aggressive-loop-optimizations -gdwarf-2 -ggdb -march=pentium -mtune=generic -Werror -Wall -Wpointer-arith -Wno-char-subscripts -Wno-multichar -Wno-unused-value -Wno-unused-const-variable -Wno-unused-local-typedefs -Wno-deprecated -Wno-unused-result -Wno-maybe-uninitialized -O1 -fno-optimize-sibling-calls -fno-omit-frame-pointer -DDBG=1 -DDLL_EXPORT_VERSION=0x502 -DMINGW_HAS_SECURE_API=1 -DUSE_COMPILER_EXCEPTIONS -DWINVER=0x502 -D_CRT_NON_CONFORMING_SWPRINTFS -D_GLIBCXX_HAVE_BROKEN_VSWPRINTF -D_M_IX86 -D_NEW_DELETE_OPERATORS_ -D_SEH_ENABLE_TRACE -D_SETUPAPI_VER=0x502 -D_USE_32BIT_TIME_T -D_WIN32_IE=0x600 -D_WIN32_WINDOWS=0x502 -D_WIN32_WINNT=0x502 -D_X86_ -D__REACTOS__ -D__i386__ -Di386 -D__ASM__ $(MINGW_INCLUDES) $(SEH_INCLUDES)

%.coffres: %.rc
	$(call run,$(RC) -i $< -o $@ -O coff,RC,$@)

ifndef REACTOS
OPTIMIZE=-O2
endif

CFLAGS=-g -Wall $(SUPPRESSED_WARNINGS) $(OPTIMIZE) $(CFLAGS_FOR_DRIVERS) $(DEFINES) $(WINDRBD_INCLUDES) $(MINGW_INCLUDES)

$(SEH_SRCDIR)%.o: $(SEH_SRCDIR)%.c
	$(CC) $(CFLAGS_FOR_SEH) -c -o $@ $<

$(SEH_SRCDIR)%.o: $(SEH_SRCDIR)%.s
	$(CC) $(ASM_CFLAGS_FOR_SEH) -c -o $@ $<

$(SEH_SRCDIR)%.o: $(SEH_SRCDIR)%.S
	$(CC) $(ASM_CFLAGS_FOR_SEH) -c -o $@ $<

%.o: %.c
	$(call run,$(CC) $(CFLAGS) -c -o $@ $<,CC,$@)

all: windrbd.sys windrbd.cat

windrbd/windrbd-event-log.rc: windrbd/windrbd-event-log.mc
	$(call run,$(MC) $< -r windrbd -h windrbd/include,MC,$@)

windrbd/include/windrbd-event-log.h: windrbd/windrbd-event-log.mc
	$(call run,$(MC) $< -r windrbd -h windrbd/include,MC,$@)

windrbd/src/printk-to-syslog.o: windrbd/include/windrbd-event-log.h

versioninfo:
	$(call run,./versioninfo.sh $(DRBDTMP) $(VERSION),VERSION,$(DRBDTMP))

.PHONY: windrbd.sys
.PHONY: windrbd.cat

$(DRBDTMP)/drbd/drbd_buildtag.c $(DRBDTMP)/drbd/windrbd_version.h &:
	./versioninfo.sh $(DRBDTMP) $(VERSION)
#	rm drbd-tmp/drbd/drbd_buildtag.o

$(DRBDTMP)/drbd/drbd_buildtag.o: versioninfo

# Extraeinladung :)
# Reason is that depend on windrbd_module.c will fail as long as there
# is not windrbd_version.
windrbd/src/windrbd_module.d: $(DRBDTMP)/drbd/windrbd_version.h

windrbd.sys: versioninfo $(TMP_DRBD_FILES) $(OBJS) $(COFFRES)
	$(call run,$(CC) -o windrbd.sys-unsigned $(OBJS) $(COFFRES) $(LIBS) $(LDFLAGS_FOR_DRIVERS) -g,LD,windrbd.sys-unsigned)
	$(call run,osslsigncode sign -key crypto/linbit-2019.pvk -certs crypto/linbit-2019.spc windrbd.sys-unsigned windrbd.sys-signed ; mv windrbd.sys-signed windrbd.sys ; rm -f windrbd.sys-unsigned,SIGN,windrbd.sys)

windrbd.cat: windrbd.sys
# build the cat file generator. It is not yet in any Linux distros ...
# if this fails then you probably forgot to clone with --recursive.
# You may want to do something like git submodule update or so..
	$(call run,make -C generate-cat-file CC=$(HOSTCC) > generate-cat-file-make.log 2>&1 || ( cat generate-cat-file-make.log && false ),MAKE,'generate-cat-file (see generate-cat-file-make.log for build logs)')
	$(call run,generate-cat-file/gencat.sh -o windrbd.cat-unsigned -h windrbd windrbd.inf windrbd.sys,GENCAT,windrbd.cat-unsigned)

# TODO: This needs a 'modern' osslsigncode (that from Ubuntu 18.04 and also
# from Ubuntu 20.04 is too old - you probably have to build it yourself)
	$(call run,rm -f windrbd.cat ;  osslsigncode sign -key crypto/linbit-2019.pvk -certs crypto/linbit-2019.spc windrbd.cat-unsigned windrbd.cat ; rm -f windrbd.cat-unsigned,SIGN,windrbd.cat)
#	rm -f windrbd.cat-unsigned

.PHONY: drbd-utils

drbd-utils:
	$(call run,cd drbd-utils && ./autogen.sh > ../drbd-utils-autogen.log 2>&1 || ( cat ../drbd-utils-autogen.log && false ),AUTOGEN,'drbd-utils (see drbd-utils-autogen.log for logs)')
	$(call run,cd drbd-utils && ./configure --without-83support --without-84support --without-drbdmon --with-windrbd --without-manual --prefix=/cygdrive/c/windrbd/usr --localstatedir=/cygdrive/c/windrbd/var --sysconfdir=/cygdrive/c/windrbd/etc --host=$(ARCH)-pc-cygwin > ../drbd-utils-configure.log 2>&1 || ( cat ../drbd-utils-configure.log && false ),CONF,'drbd-utils (see drbd-utils-configure.log for logs)')
	$(call run,make -C drbd-utils -j $(NUM_JOBS) > drbd-utils-make.log 2>&1 || ( cat drbd-utils-make.log && false ),MAKE,'drbd-utils (see drbd-utils-make.log for logs)')

clean:
	rm -f $(OBJS) $(COFFRES) 
	rm -f $(patsubst %.o,%.d,$(OBJS))
	rm -f windrbd.sys windrbd.sys.map windrbd.cat windrbd.inf
	rm -f windrbd/msg00002.bin windrbd/include/windrbd-event-log.h windrbd/windrbd-event-log.rc
	rm -f windrbd.cat-unsigned windrbd.sys-unsigned windrbd.sys-signed
	rm -rf $(DRBDTMP)
	rm -rf drbd*-tmp
	make -C generate-cat-file clean
	make -C drbd-utils clean
	rm -f drbd-utils-*.log
	rm -f generate-cat-file-*.log
	rm -f inno-setup.log

ifdef REACTOS
EXTRA_ISCC_DEFINES=/DReactos=1
endif

package: all drbd-utils
	$(call run,( cd inno-setup && $(WINE) "C:\Program Files (x86)\Inno Setup 5\iscc.exe" windrbd.iss /DWindrbdSource=.. /DWindrbdUtilsSource=..\\drbd-utils /DWindrbdDriverDirectory=$(DRIVER_DIR) /DArch=$(ARCH) $(EXTRA_ISCC_DEFINES)) > inno-setup.log 2>&1 || ( cat inno-setup.log && false ),SETUP,'windrbd (see inno-setup.log for logs)')
	tail -n 2 inno-setup.log

docker:
	$(DOCKER) build --pull=true --no-cache=true -t $(DOCKER_IMAGE) docker-root

docker-fc37:
	$(DOCKER) build --pull=true --no-cache=true -t $(DOCKER_IMAGE)-fc37 -f docker-root/Dockerfile-fc37 docker-root

docker-wine64:
	$(DOCKER) build --pull=true --no-cache=true -t $(DOCKER_IMAGE)-wine64 -f docker-root/Dockerfile-wine64 docker-root

docker-cygwin:
	$(DOCKER) build --pull=true --no-cache=true -t $(DOCKER_IMAGE)-cygwin -f docker-root/Dockerfile-cygwin docker-root

install: package-in-docker
	$(call run,inno-setup/deploy.sh inno-setup/install-$(FULL_VERSION).exe $(TARGET_IPS),INSTALL,$(FULL_VERSION) $(TARGET_IPS))

# This now generates the cocci patched DRBD sources in drbd-tmp
# subdirectory and also generates dependency files (*.d) for the
# Makefile.

NEW_TRANSFORMATIONS := $(sort $(wildcard cocci/*.cocci))

DRBD_HEADERS := $(shell find $(DRBD) -name "*.h")
DRBD_TMP_HEADERS := $(patsubst $(DRBD)%,$(DRBDTMP)%,$(DRBD_HEADERS))


# TODO: why not drbd_buildtag? */
all-dep := $(filter-out $(SEH_SRCDIR)%.d,$(filter-out $(DRBDTMP)/drbd/drbd_buildtag.d,$(OBJS:%.o=%.d)))
# all-dep := $(OBJS:%.o=%.d)

# Do not delete this intermediate files:
$(all-dep) :

# TODO: should we depend on DRBD_TMP_HEADERS here? This makes
# make copy all the headers over to drbd-tmp and patch them..
# Alternative is to use -MG (and not explicitly depend).
# from make documentation, automatic prerequisites
#
# Also do not regenerate drbd-tmp/drbd/drbd_buildtag.d this would
# trigger drbd_buildtag.c being rebuilt which also depends on
# version info and then we loop...
#
DEPEND_SCRIPT=\
	if [ $@ != $(DRBDTMP)/drbd/drbd_buildtag.d ] ; then \
		set -e; rm -f $@; \
		$(CC) -MM -MT $(patsubst %.c,%.o,$<)  $(CFLAGS) $< > $@.$$$$; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$ ; \
	fi

# $(SEH_SRCDIR)%.d: %(SEH_SRCDIR)%.c

%.d: %.c $(DRBD_TMP_HEADERS)
	$(call run,$(DEPEND_SCRIPT),DEPEND,$@)

# Do not delete the temporary headers when restarting make:
$(DRBD_TMP_HEADERS):

# $(patsubst %.c,%.o,$(TMP_DRBD_FILES)): $(DRBD_TMP_HEADERS)

#	echo $@ -> $<

ifeq ($(MAKECMDGOALS),$(filter-out clean help default install package-in-docker pull-docker all-in-docker,$(MAKECMDGOALS)))
# ifneq ($(MAKECMDGOALS),)
-include $(all-dep)
# endif
endif

COCCI_SCRIPT=\
	if [ -e drbd/drbd/compat.h ] ; then echo "Stale compat.h in DRBD sources. Do not run make in the drbd directory." ; exit 1 ; fi ; \
	mkdir -p $(shell dirname $@) && cp $< $@ ; \
	for c in $(NEW_TRANSFORMATIONS) ; do spatch --very-quiet --no-show-diff --sp-file $$c $@ --in-place ; done

$(DRBDTMP)/%.h: $(DRBD)/%.h $(NEW_TRANSFORMATIONS)
	$(call run,$(COCCI_SCRIPT),COCCI,$@)

$(DRBDTMP)/%.c: $(DRBD)/%.c $(NEW_TRANSFORMATIONS)
	$(call run,$(COCCI_SCRIPT),COCCI,$@)
