rem see https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#21295806

fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
	msg "%username%" "Please run this with Administrator privileges"
	exit
)

copy *.exe c:\windows\System32
copy drbd.inf c:\windows\inf

if exist c:\cygwin\NUL goto found_cygwin1
if exist c:\cygwin64\NUL goto found_cygwin2

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
rem this needs a path component
InfDefaultInstall ".\drbd.inf"
