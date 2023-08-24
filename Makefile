ARCH ?= x86_64
# ARCH=i686
# MINGW_SYSROOT=/home/johannes/.zeranoe/mingw-w64/i686
MINGW_SYSROOT=/home/$(USER)/.zeranoe/mingw-w64/$(ARCH)
# CC=i686-w64-mingw32-gcc
# CC=$(MINGW_SYSROOT)/bin/i686-w64-mingw32-gcc
CC=$(MINGW_SYSROOT)/bin/$(ARCH)-w64-mingw32-gcc

REACTOS_ROOT=windrbd/include/from-reactos
REACTOS_BUILD=windrbd/include/from-reactos/output-$(ARCH)

WINE=/usr/bin/wine

ifeq ($(ARCH), i686)
DRIVER_ENTRY=_DriverEntry
endif

ifeq ($(ARCH), x86_64)
DRIVER_ENTRY=DriverEntry
endif

# /cygdrive/c/Windows/System32/cmd.exe /c ms-cl-jt-win7-32bit.cmd /c /nologo /W4  /Zi  /WX  /Wv:18  /O2  /Oi  /Oy-  /GF /Gm- /Zp8 /Gz /Gs1048576 /Zc:wchar_t- /Zc:forScope /GR-  /wd4748 /wd4603 /wd4627 /wd4986 /wd4987 /wd4996  /analyze- /errorReport:queue /kernel -cbstring /d1import_no_registry /d2AllowCompatibleILVersions /d2Zi+  /wd4201 /wd4200 "-Ic:\\Ewdk1703\\Program Files\\Windows Kits\\10\\Include\\10.0.15063.0\\shared" "-Ic:\\Ewdk1703\\Program Files\\Windows Kits\\10\\Include\\10.0.15063.0\\km" "-Ic:\\Ewdk1703\\Program Files\\Windows Kits\\10\\Include\\10.0.15063.0\\km\\crt" "-Ic:\\Ewdk1703\\Program Files\\Windows Kits\\10\\Include\\10.0.15063.0\\um" -I"..\\..\\windrbd\\include" -I"." -I".\\drbd-headers" -D _X86_=1 -D i386=1 -D _M_IX86=1  -D _WIN32_WINNT=0x0502 -D WINVER=0x0502 -D WINNT=1 -D NTDDI_VERSION=0x05020000 -D KMALLOC_DEBUG=1 -D __KERNEL__=1 -D __BYTE_ORDER=1 -D __LITTLE_ENDIAN=1 -D __LITTLE_ENDIAN_BITFIELD -D COMPAT_HAVE_BOOL_TYPE=1  -D CONFIG_KREF_DEBUG=1 /FI"c:\\Ewdk1703\\Program Files\\Windows Kits\\10\\Include/10.0.15063.0\\shared\\warning.h" "drbd_buildtag.c" /c /Fo:"drbd_buildtag.obj" /Fd:"drbd_buildtag.pdb"


# TODO: __MINGW64__ also for 32 bit?
DEFINES=-D WINNT=1 -D KMALLOC_DEBUG=1 -D __KERNEL__=1 -D __BYTE_ORDER=1 -D __LITTLE_ENDIAN=1 -D __LITTLE_ENDIAN_BITFIELD -D COMPAT_HAVE_BOOL_TYPE=1  -D CONFIG_KREF_DEBUG=1 -D __MINGW64__=1

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

OBJS=$(patsubst %.c,%.o,$(DRBD_FILES)) $(patsubst %.c,%.o,$(WINDRBD_FILES))

LIBS=-lntoskrnl -lhal -lgcc -lntdll -lnetio

# CFLAGS_FOR_DRIVERS=-fPIC -fvisibility=hidden -ffunction-sections -fdata-sections -fno-builtin -ffreestanding -fno-stack-protector -mno-stack-arg-probe
# CFLAGS_FOR_DRIVERS=-fPIC -ffunction-sections -fdata-sections -fno-builtin -ffreestanding -fno-stack-protector -mno-stack-arg-probe
# CFLAGS_FOR_DRIVERS=-fPIC
# No: would not link with -lgcc
# CFLAGS_FOR_DRIVERS=-fPIC -fno-leading-underscore
# CFLAGS_FOR_DRIVERS=
CFLAGS_FOR_DRIVERS=-fPIC -fvisibility=hidden -ffunction-sections -fdata-sections -fno-builtin -ffreestanding -fno-stack-protector -mno-stack-arg-probe
# CFLAGS_FOR_DRIVERS=-fPIC


# LDFLAGS_FOR_DRIVERS=-Wl,--subsystem,native -Wl,--image-base,0x140000000 -Wl,--dynamicbase -Wl,--nxcompat -Wl,--file-alignment,0x200 -Wl,--section-alignment,0x1000 -Wl,--stack,0x100000 -Wl,--gc-sections -Wl,--exclude-all-symbols -Wl,--entry,_DriverEntry -nostartfiles -Wl,-Map='windrbd.sys.map' -static-libgcc
LDFLAGS_FOR_DRIVERS=-shared -Wl,--subsystem,native -Wl,--image-base,0x140000000 -Wl,--dynamicbase -Wl,--nxcompat -Wl,--file-alignment,0x200 -Wl,--section-alignment,0x1000 -Wl,--stack,0x100000 -Wl,--gc-sections -Wl,--exclude-all-symbols -Wl,--entry,$(DRIVER_ENTRY) -nostartfiles -nodefaultlibs -nostdlib -Wl,-Map='windrbd.sys.map'
# LDFLAGS_FOR_DRIVERS=-shared -Wl,--subsystem,native -Wl,--image-base,0x140000000 -Wl,--dynamicbase -Wl,--nxcompat -Wl,--file-alignment,0x200 -Wl,--section-alignment,0x1000 -Wl,--stack,0x100000 -Wl,--gc-sections -Wl,--exclude-all-symbols -Wl,--entry,_DriverEntry -nostartfiles -nodefaultlibs -nostdlib -Wl,-Map='windrbd.sys.map'
# LDFLAGS_FOR_DRIVERS=-shared -Wl,--subsystem,native
# LDFLAGS_FOR_DRIVERS=

CFLAGS=-g -w $(CFLAGS_FOR_DRIVERS) $(DEFINES) $(WINDRBD_INCLUDES) $(MINGW_INCLUDES)

all: versioninfo windrbd.sys windrbd.cat

versioninfo:
	./versioninfo.sh converted-sources $(VERSION)

windrbd.sys: $(OBJS)
	$(CC) -o windrbd.sys-unsigned $(OBJS) $(LIBS) $(LDFLAGS_FOR_DRIVERS)
	osslsigncode -key crypto/linbit-2019.pvk -certs crypto/linbit-2019.spc windrbd.sys-unsigned windrbd.sys-signed
	mv windrbd.sys-signed windrbd.sys

# TODO: also INF file
# TODO: needs a 'modern' osslsigncode (that from Ubuntu 18.04 is too old)
windrbd.cat: windrbd.sys
# TODO: once we can compute the windrbd.sys SHA1 hash
# TODO: and make this project a subproject.
#	generate-cat-file > windrbd.cat-unsigned
	osslsigncode -key crypto/linbit-2019.pvk -certs crypto/linbit-2019.spc windrbd.cat-unsigned windrbd.cat

clean:
	rm -f $(OBJS)
	rm -f windrbd.sys windrbd.cat

package: windrbd.sys windrbd.cat
	( cd inno-setup && $(WINE) "C:\Program Files (x86)\Inno Setup 5\iscc.exe" windrbd.iss /DWindrbdSource=.. /DWindrbdUtilsSource=Z:\\home\\johannes\\sambashare2\\drbd-utils-windows /DWindrbdDriverDirectory=$(DRIVER_DIR) )

#	$(WINE) "C:\Program Files (x86)\Inno Setup 5\iscc.exe" linstor-server.iss -DMyAppVersion=$(VERSION) -DOpenJDKDir=$(OPENJDKDIR)
