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
