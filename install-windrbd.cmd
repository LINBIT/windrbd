copy *.exe c:\windows\System32
copy *.dll c:\windows\System32
mkdir c:\windrbd
mkdir c:\windrbd\etc
mkdir c:\windrbd\etc\drbd.d
rem this needs a path component
InfDefaultInstall ".\drbd.inf"
