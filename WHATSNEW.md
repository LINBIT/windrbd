Upcoming features
-----------------

SecureBoot

Base on DRBD 9.1

LINSTOR support

What's new in version 1.0.0
---------------------------

Production readiness

What's new in version 1.0.0-rc21
--------------------------------

Do not generate a new current UUID wile IO is frozen

What's new in version 1.0.0-rc20
--------------------------------

Fixed a bug that triggered invalid page chain assertion and lead to
	connection abort at the beginning of sync. This also fixed
	a hang when changing the role (primary / secondary) while
	sync was going on.

Fixed several memory leaks.

Upgrade to DRBD 9.0.32

What's new in version 1.0.0-rc19
--------------------------------

Fixed a BSOD when syncing large volumes (This fix unveiled a PTE
	BSOD when writing from upper device to lower disk which
	was also fixed)

Fixed a BSOD on hard network shutdown (unplug network cable, this
	was actually an upstream DRBD bug)

What's new in version 1.0.0-rc18
--------------------------------

Fixed a BSOD bug in writing to event log introduced in 1.0.0-rc14

Installer: no reboot on upgrade should work now also in corner cases.

Installer: Always start user mode services (windrbdlog, windrbdumhelper)

What's new in version 1.0.0-rc17
--------------------------------

Userland services (umhelper, log) are started on boot

Upgrade to 9.0.31

Fix for install userland errors message box

Driver unloading (no reboot on Upgrade/Uninstall)

Upgrade to latest cygwin distribution

/VERYSILENT install

Setup logging

Upgrade to 9.0.30

online resize works

dynamic disks as backing devices work

What's new in version 1.0.0-rc16
--------------------------------

Fixed a bug that caused volumes with size 1-2 TB not to work properly.

What's new in version 1.0.0-rc15
--------------------------------

installer supports selection of windrbd root

fixed a bug that caused creation of lots of receiver threads when
in state Connecting (and never terminate them).

What's new in version 1.0.0-rc14
--------------------------------

Bundle basic cygwin tools so that truck based replication works without
having to install cygwin

Config key feature

Windows Event Log Support

What's new in version 1.0.0-rc13
--------------------------------

Fixed many (but not all) BSODs with verifier on.

Upgrade to DRBD 9.0.29

What's new in version 1.0.0-rc12
--------------------------------

Fixed a blue screen on disconnect: Reason was sock_really_free
called wait_event while in APC (in interrupt) and wait_event
tried to sleep.

Fixed a missing mutex_lock in
delete_multicast_elements_and_replies_for_file_object() which
caused a BSOD from time to time.

Fixed deadlock in recursive calls to rcu_read_lock (which are legal)
(rcu_read_lock (A) / synchronize_rcu (B) / rcu_read_lock (A)
where the inner rcu used to hang forever at DISPATCH_LEVEL.

WinDRBD root directory is now relocatable (currently registry key
WinDRBDRoot in HKLM/system/CurrentControlSet/services/WinDRBD
must be edited manually, no installer support yet)

What's new in version 1.0.0-rc11
--------------------------------

Updated DRBD from 9.0.25 to 9.0.28.

Fixed a system hang on disconnect: Reason was mod_timer returning
a wrong value which later caused a use-after-free of the DRBD
connection object.

Print deprecation warning when using block device interface.
This is going to be removed with the next (1.0.0-rc12) release.

Fix a NESSUS vulnerability warning: Executable path must
be quoted (in windrbdumhelper and windrbdlogger services).

Make sure there is no error 50 warning on drbdadm up.

What's new in version 1.0.0-rc10
--------------------------------

Optimization on the network side ("receiver cache"): receive from socket
in larger chunks (defaults to 128K), this speeds up secondary writes
by a factor of 2 to 4.

Fix in wait_event: wait_event should not be interruptible. Also
wait_for_completion should not be interruptible. This fixes lots
of BSODs at various places (process_sender_todo, ...) which mainly
occured at disconnecting a resource.

There is also an optimization at the backing device side (backing
device cache) but this implementation is currently broken and probably
will be abandoned (it does not give a speedup). It is disabled by default.

What's new in version 1.0.0-rc9
-------------------------------

Use device ejection API on drbdadm secondary (or down). This should
solve a BSOD on drbdadm secondary a client had.

Force open counts to 0 on drbdadm secondary (or down). This should
solve a handle leak (peer cannot be promoted to Primary) a client
had.

Updated drbd-utils shipped to 9.15.0 (was 9.12.0). Amongst other
things this makes the disconnected user mode helper work.

Use big pages for receiving sync packets (when sync target). This speeds
up sync by a factor 5 when WinDRBD is SyncTarget.

Fixed disconnect while sync bug: On disconnect wait until all
bios are completed.

What's new in version 1.0.0-rc8
-------------------------------

Fixed bug in wait_queue which caused some operations (drbdadm down right
after drbdadm up, drbdadm attach) to hang forever.

Fixed bug in backing device interface that caused I/O on backing devices
larger than 2TB to fail.

Eliminated spin_lock_irq calls

Fixed return value of timeout case in wait_event_XXX_timeout

What's new in version 1.0.0-rc7
-------------------------------

Upgraded DRBD to 9.0.25

What's new in version 1.0.0-rc6
-------------------------------

Fixed several bugs in workqueue implementation (fixes most BSODs
on disconnect while sync).

Fixed ko count mechanism (connection is more stable)

What's new in version 1.0.0-rc5
-------------------------------

Use SHA256 for signing files (EXE, SYS and CAT)

Fixed connection loss bug

Reengineered workqueues (improves system stability)

What's new in version 1.0.0-rc4
-------------------------------

Fixed boot failure introduced with 1.0.0-rc2

What's new in version 1.0.0-rc3
-------------------------------

(Probably) Fixed BSOD on upgrade as reported as issue #2 on github

What's new in version 1.0.0-rc2
-------------------------------

Fixed fio BSOD as reported as issue #2 on github

What's new in version 1.0.0-rc1
-------------------------------

Stability fixes

What's new in version 0.10.7
----------------------------

Refactored locking

Online verify

drbdadm status and drbdsetup events2 as non-Adminitrator user.

windrbd create-resource-from-url command

Installer creates WinDRBD bus device

Don't lose network printk's on boot.

windrbd set-syslog-ip command

What's new in version 0.10.6
----------------------------

Upgraded DRBD version from 9.0.17 to 9.0.22

Can set syslog-ip via boot parameters (no need to hack the
registry).

What's new in version 0.10.5
----------------------------

Key/Value based DRBD URI syntax

Minor changes to iPXE and drbd.cgi (you might want to
update those).

What's new in version 0.10.4
----------------------------

WinDRBD boot device survives network outage (sometimes).

Stability fixes (ran 26 days with continuous I/O).

----------------------------

For older changelog summaries see the version history 
at the end of README.md
