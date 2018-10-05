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

rem Also note that since the installer is 32 bit the system32
rem directory (which holds 64 bit applications, hence the name ;)
rem is called sysnative. Somehow InfDefaultInstall gets confused,
rem with this it works:

copy windrbd.sys c:\windows\sysnative\drivers
copy windrbdsvc.exe c:\windows\sysnative

rem TODO: also copy windrbdsvc.exe to some sane place
start /wait InfDefaultInstall ".\windrbd.inf"
