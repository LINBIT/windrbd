rem This is required, else if uninstall of beta4 fails, the script would
rem terminate

setlocal

if exist c:\windows\inf\drbd.inf (

start /wait msgbox.vbs
if errorlevel 7 (
	exit
)

start /wait rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 C:\windows\inf\drbd.inf
del C:\windows\inf\drbd.inf
del C:\windows\sysnative\drbdadm.exe
del C:\windows\sysnative\drbdsetup.exe
del C:\windows\sysnative\drbdmeta.exe
del C:\windows\sysnative\windrbd.exe
del C:\windows\sysnative\unzip.exe
del C:\windows\sysnative\cygwin1.dll
del C:\windows\sysnative\cygbz2-1.dll

)

endlocal
