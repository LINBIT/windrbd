First things first
==================

Clone this repository with 

	git clone --recursive <url>

else you get an incomplete checkout.

If you need installable binaries please contact Linbit (www.linbit.com)
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
the drbdadm up command.

To avoid confusion with ManTech's WDRBD we called our WDRBD-fork
WinDRBD.

What else is needed?
====================

For detailed build instructions, please see the file INSTALL. Having
said that you need a Windows 7 box with CygWin installed (Windows 10
works in theory, but hasn't been tested. Nor has Windows Subsystem for
Linux (WSL)) to run WinDRBD. For building you need Ewdk from Microsoft
and a separate Linux Box with spatch (concinelle) installed.

You need the windrbd branch of drbd-utils. To obtain it, do a:

git clone --branch windrbd --recursive https://github.com/LINBIT/drbd-utils.git

and follow the build instruction in INSTALL.windrbd file of the
repo.

To test it, we use the WIN32 API test suite in windrbd-test. This
is based on Google Test: see README.md in windrbd-test directory.

You don't need drbdcon: it does not exist in WinDRBD.

We recommend to run Windows 7 in a virtual machine and make
snapshots everytime *before* a new WinDRBD version is installed.

Differences to WDRBD
====================

The main difference is that ManTech's WDRBD stacks the DRBD devices
atop of all block devices reported by PnP manager and uses an Active
flag to control whether I/O requests are routed through DRBD or not.

In contrast Linbit's WinDRBD creates a separate Windows Device on
request (on drbdadm new-minor which is called by drbdadm up) and
uses the backing device like a normal Windows block device.

This approach has several advantages:

 * Diskless operation is supported (network only).
 * Drbdmeta can access internal meta data without special casing offsets
   larger that the DRBD device.
 * The WinDRBD doesn't need a reboot if it is changed or installed.
 * drbdcon is not needed.

Another difference is that DRBD source code is derived directly from
Linbit's sources (using spatch and patch to patch in WinDRBD specific
changes). This makes it much more easy to maintain and keep up with
DRBD 9 development.

Differences to Linux DRBD
=========================

Currently the only difference to Linux DRBD is that block devices 
are specified as you would expect it under Microsoft Windows, that
is drive letters and GUID's are used. Examples:

	disk "F:";
	# or:
	disk "0b098289-8295-11e7-bddb-0800274272c4";

We recommend not to assign drive letters to backing devices, since 
that easily may confuse the user.

Starting with 0.4.8 windrbd refuses to attach to a device containing
a file system known to Windows. We do so because Windows accesses
the file system independently of DRBD causing data corruption.

Use

	windrbd hide-filesystem <drive-letter>

to prepare the backing device for use with windrbd. You can undo
that later with

	windrbd show-filesystem <drive-letter>

however only when the device is not attached.

Logging
=======

Since WinDRBD is at a very early development stage, logging is very
important. We use syslog UDP packets and a Linux host to debug
WinDRBD.

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

 * 0.1 (Oct 25, 2017): Basic I/O works with separate DRBD device.
 * 0.2 (Nov 13, 2017): Creation and basic usage of NT filesystem on DRBD 
		    device works.
 * 0.2.1 (Nov 16, 2017): Patch bootsector to hide NTFS on backing device
		    from NTFS driver.
 * 0.3.0 (Dec 20, 2017): Connection from windrbd to Linux DRBD works.
 * 0.3.1 (Dec 20, 2017): Fixed a blue screen introduced with 0.3.0
 * 0.3.2 (Dec 21, 2017): Implemented device open and close methods.
 * 0.3.3 (Dec 26, 2017): Connection from Linux DRBD to windrbd also works.
 * 0.3.4 (Jan 05, 2018): Fixed several blue screens.
 * 0.3.5 (Jan 09, 2018): Fixed additional blue screen when connected.
 * 0.3.6 (Jan 09, 2018): Updated version of DRBD this is based on.
 * 0.3.7 (Jan 11, 2018): Local I/O works again.
 * 0.4.0 (Jan 12, 2018): Removed lots of legacy code.
 * 0.4.1 (Jan 19, 2018): Sync is almost working.
 * 0.4.2 (Jan 22, 2018): Support for I/O to/from backing device with more
			 than 32 pages (needed to split requests).
 * 0.4.3 (Jan 26, 2018): Fixed a blue screen.
 * 0.4.4 (Jan 27, 2018): Fixed a blue screen on system shutdown.
 * 0.4.5 (Jan 29, 2018): Fixed a data integrity error on sync
 * 0.4.6 (Feb 06, 2018): supend-io and resume-io should work (quorum not)
 * 0.4.7 (Feb 07, 2018): Fixed a Windows 10 blue screen when accessing the
			 windrbd device.
 * 0.4.8 (Feb 15, 2018): Refuse to attach to a backing device containing
			 a (known) file system.
 * 0.4.9 (Feb 16, 2018): Fixed a blue screen introduced in last commit.
 * 0.5.0 (Feb 27, 2018): Beta 1
 * 0.5.1 (Mar 14, 2018): Implemented flushing in windrbd device.
 * 0.5.2 (Mar 20, 2018): Auto-hide filesystem on attach (user space changes
			 only).
 * 0.5.3 (Mar 28, 2018): Assign drive letter from drbd.conf
 * 0.5.4 (Mar 28, 2018): Fixed blue screen on drbdadm down and no mount point.
 * 0.6.0 (Mar 29, 2018): Beta 2: Usability improvements.
 * 0.6.1 (Apr 17, 2018): Use Mountmanager to create Symlinks.
 * 0.6.2 (Apr 17, 2018): Fixed reference count error on drbdadm down introduced
                         with last release.
 * 0.6.3 (Apr 24, 2018): Fixed blue screen on writing while connected.
 * 0.6.4 (May 08, 2018): Fixed very slow sync performance problem (and upgraded
                         to DRBD 9.0.13).
 * 0.6.5 (May 09, 2018): Fixed memleaks introduced with last release.
 * 0.6.6 (May 11, 2018): Upgraded to DRBD 9.0.14, solving broken split brain
                         handling.
 * 0.6.7 (May 14, 2018): Fixed pachting bootsector. Patch is not propagated to
			 peers.
 * 0.7.0 (May 15, 2018): Beta 3: Stability fixes
 * 0.7.1 (May 24, 2018): Notify Windows explorer about new disk drive(s) (user
			 space only)
