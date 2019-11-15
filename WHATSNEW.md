This is the version history of WinDRBD. It is placed here
instead of README.md because here one can find it quicker.
For more detailed information on WinDRBD please read
README.md and the documentation provided by Linbit at

    https://downloads.linbit.com/

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
