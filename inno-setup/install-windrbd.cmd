rem see https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#21295806

fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
	msg "%username%" "Please run this with Administrator privileges"
	exit
)

rem Only left over copy: We use this in the uninstall script,
rem however on install it must be in the same folder as the
rem sys file.
copy windrbd.inf c:\windows\inf

rem cygrunsrv.exe -I windrbdlog -p /cygdrive/c/windrbd/usr/sbin/windrbd.exe -a log-server -1 /cygdrive/c/windrbd/windrbd-kernel.log -2 /cygdrive/c/windrbd/windrbd-kernel.log -t manual
rem cygrunsrv.exe -I windrbdumhelper -p /cygdrive/c/windrbd/usr/sbin/windrbd.exe -auser-mode-helper-daemon -1 /cygdrive/c/windrbd/windrbd-umhelper.log -2 /cygdrive/c/windrbd/windrbd-umhelper.log -t manual

rem this installs the bus device (new in 0.10.0)
rem This currently does not work. Fix it and reenable this:
rem windrbd install-bus-device .\windrbd.inf

rem start /wait InfDefaultInstall .\windrbd.inf
rem start /wait rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 .\windrbd.inf
start /wait rundll32.exe advpack.dll,LaunchINFSectionEx .\windrbd.inf,,,4,N
rem start /wait rundll32.exe advpack.dll,LaunchINFSectionEx .\<file>.inf,,,20
rem start /wait rundll32.exe advpack.dll,LaunchINFSection .\<file>.inf,DefaultInstall,1
