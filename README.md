First things first
==================

Clone this repository with 

	git clone --recursive <url>

else you get an incomplete checkout.

If you need installable binaries with a signed driver please go to

https://www.linbit.com/en/drbd-community/drbd-download/

(scroll down to DRBD 9 Windows Driver)

If you need support, please contact Linbit (www.linbit.com)
at sales@linbit.com

What is WinDRBD?
================

WinDRBD is a port of Linbit's Distributed Replicated Block Device
Linux driver to Microsoft Windows. Technically it is a thin
emulation layer that maps Linux specific kernel API calls to the
Microsoft Windows NT Kernel API.

DRBD itself is used to build High Availability clusters by replicating
contents of one block device over a network to (up to 31) other nodes.

WinDRBD is based on DRBD 9. It was originally started by Korean
company Mantech and later resigned by Johannes Thoma for Linbit
to match more closely the Linux device model. In particular the
DRBD devices are not stacked over existing Windows devices (like
Mantech WDRBD does it) but creates DRBD devices upon creation with
the drbdadm primary command.

To avoid confusion with ManTech's WDRBD we called our WDRBD-fork
WinDRBD.

What else is needed?
====================

If you have a binary package, you don't need to install CygWin since
the Cygwin DLL comes with the binary package. Commands like drbdadm and
windrbd should work out-of-the-box with the Windows cmd shell.

For detailed build instructions, please see the file INSTALL. Having
said that you need a Windows 7 box with CygWin installed (Windows 10
and Windows Server 2016 also work) and a Linux box to build WinDRBD
from source.

For building you need Ewdk from Microsoft and a separate Linux Box
with spatch (concinelle) installed.

You need at least version 9.7.0 of drbd-utils. To obtain it, do a:

git clone --recursive https://github.com/LINBIT/drbd-utils.git

and follow the build instruction in README-windrbd.md file of the
repo.

To test it, we use the WIN32 API test suite in windrbd-test. This
is based on Google Test: see README.md in windrbd-test directory.

You don't need drbdcon: it does not exist in WinDRBD.

We recommend to run Windows in a virtual machine and make
snapshots everytime *before* a new WinDRBD version is installed.

Please also note that once you have installed an officially
verified version of WinDRBD (you can get one from Linbit),
you cannot install self-signed versions of WinDRBD over them.
In other words if you wish to compile WinDRBD by yourself,
do not install official packages on your test machines.
In addition if you use self signed (self compiled) packages,
you have to put Windows into Test mode, else it will refuse
to boot. To do so, execute

bcdedit /set TESTSIGNING ON

as Administrator and reboot the machine. It then should display
Testmode in the lower right corner when it comes up again.

Configuring DRBD
================

The DRBD config files can be found in following folder:

	C:\windrbd\etc

Put your resources (extension .res) into the C:\windrbd\etc\drbd.d
folder (from within a CygWin shell you can access this via

	/cygdrive/c/windrbd/etc/drbd.d/<name>.res

Then with

	drbdadm up <name>

you can bring your DRBD resource up. Please refer to the DRBD
Users guide (be sure to pick the 9.0 version) for more information
of how to configure and administrate DRBD. Most drbdadm commands
should work exactly like with the Linux version of DRBD.

There is also a WinDRBD specific tech guide which explains how
to prepare two Windows Server 2016 nodes for use with WinDRBD.
Please see the Linbit website for that guide.

Differences to WDRBD
====================

Note: If you don't know ManTech's WDRBD, you can skip reading
this section.

The main difference is that ManTech's WDRBD stacks the DRBD devices
atop of all block devices reported by PnP manager and uses an Active
flag to control whether I/O requests are routed through DRBD or not.

In contrast Linbit's WinDRBD creates a separate Windows Device on
request (on drbdadm primary) and uses the backing device like a
normal Windows block device.

This approach has several advantages:

 * Diskless operation is supported (network only).
 * Drbdmeta can access internal meta data without special casing offsets
   larger that the DRBD device.
 * Later, the WinDRBD driver doesn't need a reboot if it is changed
   (currently it does not need a reboot if installed freshly).
 * drbdcon is not needed, thereby lots of race conditions simply just
   don't exist on WinDRBD.

Another difference is that DRBD source code is derived directly from
Linbit's sources (using spatch and patch to patch in WinDRBD specific
changes). This makes it much more easy to maintain and keep up with
DRBD 9 development (current WinDRBD releases are based on DRBD 9.0.16).

Differences to Linux DRBD
=========================

Currently the only difference to Linux DRBD is that block devices 
are specified as you would expect it under Microsoft Windows, that
is drive letters or GUID's are used. Examples:

	disk "F:";
	# or:
	disk "0b098289-8295-11e7-bddb-0800274272c4";

We recommend not to assign drive letters to backing devices, since 
that easily may confuse the user. You can use the mountvol utility
to find the GUID of a device.

Starting with 0.4.8 windrbd refuses to attach to a device containing
a file system known to Windows. We do so because Windows accesses
the file system independently of DRBD causing data corruption.

Starting from 0.5.2 if drbdadm detects a file system (NTFS) on
the backing device, it automatically hides it from Windows.

To do that manually, use

	windrbd hide-filesystem <drive-letter>

to prepare the backing device for use with windrbd. You can undo
that later with

	windrbd show-filesystem <drive-letter>

however only when the device is not attached.

Starting from 0.5.3, the device entry has following format:

	device <drive-letter> minor <unique-minor>;

for example:

	device "K:" minor 1;

This makes the WinDRBD device appear as drive K: once the
drbdadm primary <res> command is executed (before 0.7.2 it
also existed on drbdadm up, but this couldn't be accessed,
so we changed that to drbdadm primary). Starting from 0.7.1,
your shell (Windows Explorer in most cases) gets notified
about the new drive, so you probably will get a panel that
asks you if the drive should be formatted.

Starting with 0.10.1, we distinguish between data devices
and disk devices. Data devices are regular block devices
with a mount point. They can be formatted with NTFS, other
file systems like FAT family and ReFS are not yet supported.

Disk devices present themselves as a regular PnP disk
(like a physical hard disk) and appear as disk in the
Windows partition manager (and also in device manager).
With partition manager a partition table can be created
and then paritions (with assigned drive letters) can
be created on the disk. The partitions can be formatted
with all supported file systems. The drawback however is
that there must be a partition table on the disk (under
Linux, kpartx can be used to create device nodes for
each partition).

Example for a disk device would be:

	device minor 42;

(with no mount point). Mount points can be assigned with
partition manager.

A special case of the disk device is the boot device. Booting
from a remote (Linux) server is possible now (however 
without local backing storage and installation is quite
difficult now). There is a document on 

	https://downloads.linbit.com/

("Setting up WinDRBD diskless boot") that describes the
process (which is subject to change).

Current limitations
===================

Our planned 1.0 release will have following restrictions:

  * Auto-promote is not supported.

  * No 32-Bit version is supported, only 64 bit.

  * Windows 7 is minimum (no Vista, no XP) (SP1 required (?))

We might fix following current (0.7.4) restrictions for the
1.0 release:

  * Right now only NTFS is supported atop the windrbd device.
    (or you can use the device as a RAW device).

  * On installation (or upgrade) a system reboot is required.

  * Of the DRBD features, the following are currently unsupported:
    discard, biosets, debugfs, online verify, RB_CONGESTED_REMOTE,
    write same, disk stats, trimming.

Following works starting from 0.10.0):

  * System Volume (C:) can be used for windrbd (however without 
    local backing storage for now).

Please also check the file FEATURES in the repository.

Logging
=======

To view the log file go to

	C:\windrbd\windrbd-kernel.log

If you need remote logging, please read on.

We use syslog UDP packets and a Linux host to debug WinDRBD.

To configure the log host set a Registry key (string value):

	Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\drbd\syslog_ip

and assign it the IP address (you have to reload the WinDRBD driver
after setting this, currently you have to reboot the machine).

You can also log on the Windows machine directly by starting

	windrbd log-server [-o logfile]

However the last log messages before a blue screen will be lost, then.

If you are logging to the local Windows machine, use 127.0.0.1 as
IP address (this is the default). Do not specify a network interface
IP, this might cause the system to hang on boot.

See also file INSTALL for more instructions.

Version history
===============

Please see the file WHATSNEW for the Version history.
