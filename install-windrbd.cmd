rem see https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#21295806

fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
	msg "%username%" "Please run this with Administrator privileges"
	exit
)

rem This is required, else if uninstall of beta4 fails, the script would
rem terminate

setlocal

pause

rem TODO: use PATH instead
copy *.exe c:\windows\System32
rem needed?
copy windrbd.inf c:\windows\inf

if exist c:\cygwin\NUL goto found_cygwin1
if exist c:\cygwin64\NUL goto found_cygwin2

rem TODO: this is not a good idea
copy *.dll c:\windows\System32
goto next

:found_cygwin1
copy c:\cygwin\bin\cygwin1.dll c:\windows\System32
copy c:\cygwin\bin\cygbz2-1.dll c:\windows\System32
goto next

:found_cygwin2
copy c:\cygwin64\bin\cygwin1.dll c:\windows\System32
copy c:\cygwin64\bin\cygbz2-1.dll c:\windows\System32
goto next

:next
if exist c:\windrbd\NUL goto keep_settings

mkdir c:\windrbd
unzip -d c:\windrbd sysroot.zip


:keep_settings

rem Also note that since the installer is 32 bit the system32
rem directory (which holds 64 bit applications, hence the name ;)
rem is called sysnative. Somehow InfDefaultInstall gets confused,
rem with this it works:

copy windrbd.sys c:\windows\sysnative\drivers
start /wait InfDefaultInstall ".\windrbd.inf"

pause
 


endlocal

