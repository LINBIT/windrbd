copy *.exe c:\windows\System32

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
