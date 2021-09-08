This directory contains the '/' directory of the WinDRBD user
space utilities. The path can be configured at installation time
and modified by editing the WinDRBDRoot registry value in the
WinDRBD service key:

	HKLM\System\CurrentControlSet\Services\WinDRBD\WinDRBDRoot

Note that the path must be specified in cygwin format, use the
cygpath utility to convert the path name.

For the binary distribution, the windrbd utils binaries are installed
to <windrbd-root>\usr\sbin. This directory is also added to the
PATH variable (you might have to restart your shell after WinDRBD
installation).

There is no need to install CygWin with WinDRBD, since windrbd binary
distribution comes with a bundled cygwin DLL. You might have to
replace it later if you install cygwin later (cygwin will complain
about the bundled DLL).

Also note that the cygwin1.dll that comes with WinDRBD might conflict
with your CygWin installation. If it does, remove the cygwin1.dll
from the <windrbd-root>\usr\sbin folder.

If you are upgrading to a newer WinDRBD version, setup might complain
about *.exe files (most notably windrbd.exe) which it cannot replace.
In that case, open a cmd prompt and execute:

sc stop windrbdumhelper
sc stop windrbdlog

Also make sure that no drbdsetup events2 daemon is running (if you
should have started it manually).
