rem @echo on

rem /COPYALL doesn't work, not enough rights
robocopy /MIR /COPY:DT "." "c:\program files\drbd"

rem https://msdn.microsoft.com/en-us/windows/hardware/drivers/devtest/verifier-command-line
verifier  /standard  /driver drbd.sys

rem We will work without signatures, maybe throw this away.
"c:\program files\drbd\setup\certmgr.exe" -add "c:\program files\drbd\setup\linbit.cer" -s -r localMachine ROOT
"c:\program files\drbd\setup\certmgr.exe" -add "c:\program files\drbd\setup\linbit.cer" -s -r localMachine TRUSTEDPUBLISHER

rem This does the actual driver install. Not sure if we want this since
rem DRBD is then loaded on boot which is not what we want (if it crashes
rem on load there is no chance to boot windows again, not even in Safe
rem mode).
%SystemRoot%\System32\InfDefaultInstall.exe "c:\program files\drbd\setup\drbd.inf"
