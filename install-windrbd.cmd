rem see https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#21295806

fsutil dirty query %systemdrive% >nul
if %errorlevel% NEQ 0 (
	msg "%username%" "Please run this with Administrator privileges"
	exit
)

if not exist c:\windows\inf\drbd.inf goto no_legacy
set /p a="A WinDRBD beta4 installation was found. We will uninstall it, since it conflicts with WinDRBD beta5 (and above) installations. Type yes to continue. Anything else cancels the installation without touching anything: "
if not %a% == yes (
	exit
)
rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 C:\windows\inf\drbd.inf

:no_legacy

copy *.exe c:\windows\System32
copy windrbd.inf c:\windows\inf

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
