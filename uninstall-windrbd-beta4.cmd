rem This is required, else if uninstall of beta4 fails, the script would
rem terminate

setlocal

if exist c:\windows\inf\drbd.inf (

start /wait msgbox.vbs
if errorlevel 7 (
	msg "%username%" "Installation cancelled"
	exit
)

start /wait rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 C:\windows\inf\drbd.inf
del C:\windows\inf\drbd.inf

)

endlocal
