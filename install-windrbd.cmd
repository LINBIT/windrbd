copy *.exe c:\windows\System32
copy *.dll c:\windows\System32

if exist c:\windrbd\NUL goto keep_settings

mkdir c:\windrbd
unzip -d c:\windrbd sysroot.zip

:keep_settings
rem this needs a path component
InfDefaultInstall ".\drbd.inf"
