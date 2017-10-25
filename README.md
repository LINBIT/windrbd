What is WinDRBD?
================

WinDRBD is a port of Linbit's Distributed Replicated Block Device
Linux driver to Linux. Technically it is a thin emulation layer
that maps Linux specific kernel API calls to the Microsoft Windows 
NT Kernel API.

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

You need the windrbd branch of drbd-utils. 

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

.) Diskless operation is supported (network only).
.) Drbdmeta can access internal meta data without special casing offsets
   larger that the DRBD device.
.) The WinDRBD doesn't need a reboot if it is changed or installed.
.) drbdcon is not needed.

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

Version 0.1 only: The drive letter for the DRBD device (the one 
you will be working with) is derived from the DRBD minor, where
C => minor 0, D => minor 1 and so on. So when specifying

         device /dev/drbd5;

the DRBD device would be H: (internally however it will be \\Device\\Drbd5)

This restriction will be fixed soon.

Version history
===============

0.1 (Oct 25, 2017): Basic I/O works with separate DRBD device.
