rem see https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#21295806

fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
	msg "%username%" "Please run this with Administrator privileges"
	exit
)

rem needed?
copy windrbd.inf c:\windows\inf

if not exist c:\windrbd\NUL (
	mkdir c:\windrbd
	unzip -d c:\windrbd sysroot.zip
)

copy windrbd*.exe c:\windrbd\usr\sbin
copy drbd*.exe c:\windrbd\usr\sbin

cygrunsrv.exe -I windrbdlog -p /cygdrive/c/windrbd/usr/sbin/windrbd.exe -a log-server -1 /cygdrive/c/windrbd/windrbd-kernel.log -2 /cygdrive/c/windrbd/windrbd-kernel.log -t manual
cygrunsrv.exe -I windrbdumhelper -p /cygdrive/c/windrbd/usr/sbin/windrbd.exe -auser-mode-helper-daemon -1 /cygdrive/c/windrbd/windrbd-umhelper.log -2 /cygdrive/c/windrbd/windrbd-umhelper.log -t manual

start /wait InfDefaultInstall ".\windrbd.inf"
