rem see https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#21295806

fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
        msg "%username%" "Please run this with Administrator privileges"
        exit
)

drbdadm down all

rem TODO: uninstall userland tools (drbdadm.exe, ...) from C:\Windows\System32
rem TODO: stop DRBD service (kernel driver) .. make it stoppable
rem sc stop drbd
rem TODO: also install inf file (under C:\Windows\inf) and use it
rem for uninstall.

rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 Y:\windrbd\converted-sources\drbd\drbd.inf
