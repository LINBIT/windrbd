rem see https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#21295806

fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
	msg "%username%" "Please run this with Administrator privileges"
	exit
)

drbdadm down all
rem Later: (this currently might BSOD if there are resources up.
rem Right now need to reboot after uninstall.
rem sc stop windrbd
sc stop windrbdlog
sc stop windrbdumhelper

cygrunsrv -R windrbdlog
cygrunsrv -R windrbdumhelper

rem This currently does not work: fix it and reenable this:
rem windrbd remove-bus-device C:\windows\inf\windrbd.inf

rem start /wait rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 C:\windows\inf\windrbd.inf

