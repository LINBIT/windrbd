rem see https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#21295806

fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
	msg "%username%" "Please run this with Administrator privileges"
	exit
)

rem drbdadm down all

rem TODO: uninstall userland tools (drbdadm.exe, ...) from C:\Windows\System32
rem TODO: stop DRBD service (kernel driver) .. make it stoppable
rem sc stop drbd
rem TODO: also install inf file (under C:\Windows\inf) and use it
rem for uninstall.

start /wait rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 C:\windows\inf\windrbd.inf
pause
echo hallo
del C:\windows\inf\windrbd.inf
del C:\windows\sysnative\drivers\windrbd.sys
pause
