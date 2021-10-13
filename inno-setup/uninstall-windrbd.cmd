rem see https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#21295806

fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
	msg "%username%" "Please run this with Administrator privileges"
	exit
)

rem Don't do that .. it will start the kernel driver with sc start windrbd
rem again which causes it not to unload later. It is done in windrbd.iss
rem (procedure stopDriver)
rem drbdadm down all
rem This is done in the windrbd.iss stopDriver now:
rem sc stop windrbd
sc stop windrbdlog
sc stop windrbdumhelper

cygrunsrv -R windrbdlog
cygrunsrv -R windrbdumhelper

rem This is done in stopDriver section of windrbd.iss
rem windrbd remove-bus-device C:\windows\inf\windrbd.inf

start /wait rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 C:\windows\inf\windrbd.inf

