rem @echo on

cd /D ".."


rem /COPYALL doesn't work, not enough rights
robocopy /MIR /COPY:DT "." "c:\program files\drbd"


rem hangs on boot, waits for windbg
rem bcdedit /bootdebug on 

rem JT: we are currently not using the windows kernel level
rem debugger, so we also don't need those two lines for now.
rem bcdedit /debug on 
rem bcdedit /dbgsettings serial debugport:1 baudrate:115200

rem bcdedit /set TESTSIGNING ON
rem isn't enough

rem https://msdn.microsoft.com/en-us/windows/hardware/drivers/devtest/verifier-command-line
verifier  /standard  /driver drbd.sys

"c:\program files\drbd\setup\certmgr.exe" -add "c:\program files\drbd\setup\linbit.cer" -s -r localMachine ROOT
"c:\program files\drbd\setup\certmgr.exe" -add "c:\program files\drbd\setup\linbit.cer" -s -r localMachine TRUSTEDPUBLISHER

rem rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 0 "c:\program files\drbd\inf\bin\drbd.inf"
%SystemRoot%\System32\InfDefaultInstall.exe "c:\program files\drbd\setup\drbd.inf"
goto :exit











rem change drive, too...
cd /D "%0\.."


runas /user:administrator      mkdir "c:\program files\drbd\"
runas /user:administrator      mkdir "c:\program files\drbd\bin"
runas /user:administrator      mkdir "c:\program files\drbd\etc"

runas /user:administrator      xcopy /E /L /H /Y "src\git-complete\build\drbd\x86\bin\" "c:\program files\drbd\bin\"
runas /user:administrator      xcopy /E /L /H /Y "src\git-complete\build\drbd\x86\etc\" "c:\program files\drbd\etc\"


runas /user:administrator      rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 0 ".\src\git-complete\build\drbd\x86\Win7Debug\bin\drbd.inf"

rem %SystemRoot%\System32\InfDefaultInstall.exe ".\src\git-complete\build\drbd\x86\Win7Debug\bin\drbd.inf"

pause

:exit
