First things first
==================

Clone this repository with 

	git clone --recursive <url>

else you get an incomplete checkout.

If you need installable binaries with a signed driver please go to

https://linbit.com/linbit-software-download-page-for-linstor-and-drbd-linux-driver/#drbd-windows

If you need support, please contact Linbit (www.linbit.com)
at sales@linbit.com

What is WinDRBD?
================

WinDRBD is a port of Linbit's Distributed Replicated Block Device
Linux driver to Microsoft Windows. Technically it is a thin
compatibility layer that maps Linux specific kernel API calls to the
Microsoft Windows NT Kernel API.

DRBD itself is used to build High Availability clusters by replicating
contents of block devices over a network to (up to 31) other nodes.

WinDRBD is based on DRBD 9. It was originally started by Korean
company Mantech and was later rewritten by an Austrian programmer called
Johannes Thoma for Linbit.

DRBD devices are exported as SCSI disks as soon as the resource
becomes primary and can be partitioned and formatted with the
standard Windows tools (diskpart, partition editor in control
panel).

What else is needed?
====================

If you have a binary package, you don't need to install CygWin since
the Cygwin DLL comes with the binary package. Commands like drbdadm and
windrbd should work out-of-the-box with the Windows cmd shell.

We strongly recommend to use the binary packages provided by
Linbit since they are signed with a DigiCert key and therefore
should load without putting Windows into test mode. Note that
WinDRBD does not support SecureBoot currently but we are working
on this.

For detailed build instructions, please see the file INSTALL. Having
said that you need a Windows 7 box with CygWin installed (Windows 10
and Windows Server 2016 also work) and a Linux box to build WinDRBD
from source.

For building you need Ewdk from Microsoft and a separate Linux Box
with spatch (concinelle) installed.

You need a recent version of drbd-utils. To obtain it, do a:

git clone --recursive https://github.com/LINBIT/drbd-utils.git

and follow the build instruction in README-windrbd.md file of the
repo.

Configuring DRBD
================

The DRBD config files can be found in following folder:

	C:\windrbd\etc

This folder can be configured at installation time (use this for
example if your C: drive is read only).

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

Differences to Linux DRBD
=========================

In the configuration the only difference to Linux DRBD is that block
devices are specified as you would expect it under Microsoft Windows,
that is drive letters or GUID's are used. Examples:

	disk "F:";
	# or:
	disk "0b098289-8295-11e7-bddb-0800274272c4";

We recommend not to assign drive letters to backing devices, since 
that easily may confuse the user. You can use the mountvol utility
to find the GUID of a device.

Disk devices present themselves as a regular SCSI disk
(like a physical hard disk) and appear as disk in the
Windows partition manager (and also in device manager).
With partition manager a partition table can be created
and then paritions (with assigned drive letters) can
be created on the disk. The partitions can be formatted
with all supported file systems. This means that
that normally there is be a partition table on the disk (under
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

  * No read access when there are only secondaries.

  * For booting via WinDRBD the installation onto a WinDRBD volume
    is not possible yet with the Windows installer GUI.

  * Currently no 32-Bit version is supported, only 64 bit.

  * No SecureBoot support yet (we are working on this one). 

Logging
=======

To view the log file go to

	C:\windrbd\windrbd-kernel.log

If you need remote logging, please read on.

We use syslog UDP packets and a Linux host to debug WinDRBD.

To configure the log host set a Registry key (string value):

	Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\drbd\syslog_ip

and assign it the IP address.

You can use 

	windrbd set-syslog-ip ipv4-address

to change the syslog IP for this session (the registry key is only
evaluated at server start).

If you are logging to the local Windows machine, use 127.0.0.1 as
IP address (this is the default).

There is also a logfile written by the installer located in the
%TEMP% directory. It should be consulted when something with the
installation goes wrong.

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
 * 0.7.2 (May 28, 2018): Windows device only exists while primary.
 * 0.7.3 (Jun 15, 2018): Networking fixes
 * 0.7.4 (Jun 19, 2018): Error handling on backing device (with fault injection)
 * 0.8.0 (Jul 06, 2018): Beta 4: First public beta
 * 0.8.1 (Jul 10, 2018): Handling unplugging USB stick should work now.
 * 0.8.2 (Jul 31, 2018): Split WinDRBD requests into 1Meg pieces for DRBD
 * 0.8.3 (Aug 01, 2018): Fixed BSOD requests > 1Meg and backing dev failure.
 * 0.8.4 (Aug 02, 2018): Performance: do not split into 4K requests.
 * 0.8.5 (Aug 15, 2018): Fault injection framework, fixed permissions
 * 0.8.6 (Aug 27, 2018): Kernel interface now based on ioctl() instead of TCP/IP
 * 0.8.7 (Sep 03, 2018): User mode helpers, do not load driver on boot
 * 0.8.8 (Sep 17, 2018): kmalloc() debugger. For driver unload to work someday.
 * 0.8.9 (Sep 27, 2018): Uninstall works (but needs reboot), switched to
			 inno-setup for installation.
 * 0.8.10 (Oct 10,2018): Autostarting user mode helper and log server as
			 Windows Services.
 * 0.8.11 (Oct 12,2018): Report kernel driver versions over ioctl's
 * 0.8.12 (Oct 17,2018): Upgraded DRBD to 9.0.15
 * 0.8.13 (Oct 30,2018): Fixed memory leak in I/O path
 * 0.8.14 (Nov 02,2018): Upgraded DRBD to 9.0.16
 * 0.8.15 (Nov 13,2018): Sendbuffer limit, fixed BSOD on I/O while connected
 * 0.8.16 (Nov 14,2018): Some last fixes to installer
 * 0.8.17 (Nov 16,2018): Fixed sync stall bug
 * 0.8.18 (Nov 21,2018): Disallow driver unload when there are resources up
 * 0.8.19 (Nov 29,2018): Tech guide
 * 0.9.0 (Dec 03, 2018): Public beta
 * 0.9.1 (Dec 04, 2018): Fixed a buffer overflow in user space utility
 * 0.9.2 (Apr 10, 2019): DRBD 9.0.17, support for n > 2 nodes
 * 0.10.0 (Oct 15, 2019): Use WinDRBD device as system root ("C:\") (without
			  local backing storage and in VMs only).
 * 0.10.1 (Nov 6, 2019): Data devices and Disk devices work again.
 * 0.10.2 (Nov 14,2019): iPXE passes network address to kernel: no need for
			 static IP and StartType registry patch for booting.
 * 0.10.3 (Nov 18,2019): Fixed logging (IP address was hardcoded)
 * 0.10.4 (Jan 31,2020): Stability fixes
 * 0.10.5 (Mar 03,2020): Key/Value based boot config
 * 0.10.6 (Apr 1, 2020): Upgraded DRBD to 9.0.22
 * 0.10.7 (May 6, 2020): Online verify, drbdadm status as non-admin and other
			 useful mini-features (see WHATSNEW.md).
 * 1.0.0-rc1 (Jul 3, 2020): Stability fixes
 * 1.0.0-rc2 (Jul 30, 2020): Fixed fio BSOD
 * 1.0.0-rc3 (Aug 4, 2020): Fixed BSOD on upgrade
 * 1.0.0-rc4 (Aug 5, 2020): Fixed boot failure introduced with 1.0.0-rc2
 * 1.0.0-rc5 (Sep 14, 2020): Reengineered workqueues, stability fixes.
 * 1.0.0-rc6 (Oct 8, 2020): Fixed workqueues and ko-count mechanism
 * 1.0.0-rc7 (Oct 14, 2020): Upgrade to DRBD 9.0.25
 * 1.0.0-rc8 (Nov 6, 2020): Fixed many lockups, fixed 2TB limit
 * 1.0.0-rc9 (Dec 11, 2020): Optimized SyncTarget, many fixes when becoming
			     secondary and fixed BSOD on disconnect while sync
 * 1.0.0-rc10 (Feb 24, 2021): Optimized secondary writes, fixed wait_event and
                              completions (they should be non-interruptible)
 * 1.0.0-rc11 (Apr 26, 2021): Upgrade to DRBD 9.0.28, Fixed mod_timer causing
                              system hang on disconnect
 * 1.0.0-rc12 (May 17, 2021): Fixed 3 stability issues, drbd utils support
			      relocation. Now ran 5 days in disconnect/connect
			      loop without issues.
 * 1.0.0-rc13 (Aug 2, 2021): Upgrade to DRBD 9.0.29, fixed most issues found
			     by driver verifier.
 * 1.0.0-rc14 (Sep 14, 2021): Event log, config key, bundle sed and bash
 * 1.0.0-rc15 (Sep 23, 2021): Installer prompts for install paths.
 * 1.0.0-rc16 (Sep 30, 2021): Fixed a bug that caused volumes with size 1-2 TB not to work properly.
 * 1.0.0-rc17 (Oct 22, 2021): Online resize, no reboot on upgrade/uninstall and
                              many other improvements (see WHATSNEW.md)
 * 1.0.0-rc18 (Nov 5, 2021): Installer and event log BSOD fixes
