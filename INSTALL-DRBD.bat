@echo OFF


rem change drive, too...
cd /D "%0\.."


rem .
rem The admin cannot access network drives;
rem the user cannot write to the "Program Files" directory.
rem There's no "ZIP" or "TAR", so we need to make a temporary copy.
rem .

set TMPCPYDIR="%Temp%\drbd"

mkdir "%TMPCPYDIR%"
mkdir "%TMPCPYDIR%\bin"
mkdir "%TMPCPYDIR%\etc"
mkdir "%TMPCPYDIR%\etc\drbd.d"
mkdir "%TMPCPYDIR%\setup"
mkdir "%TMPCPYDIR%\var"
mkdir "%TMPCPYDIR%\var\lock"
mkdir "%TMPCPYDIR%\var\lib"
mkdir "%TMPCPYDIR%\var\lib\drbd"
mkdir "%TMPCPYDIR%\var\run"
mkdir "%TMPCPYDIR%\var\run\drbd"

rem /COPYALL doesn't work, not enough rights
rem robocopy /MIR /COPY:DT "src\git-complete\build\drbd" "%TMPCPYDIR%"
copy "%0\..\..\drbd-utils\user\v9\*.exe" "%TMPCPYDIR%\bin"
rem copy "c:\cygwin64\bin\cygwin1.dll" "%TMPCPYDIR%\bin"
copy "c:\cygwin64\bin\cygwin1.dll" "%TMPCPYDIR%\bin"

copy "..\converted-sources-working-copy\drbd\drbd.sys" "%TMPCPYDIR%\setup"
copy "..\converted-sources-working-copy\drbd\drbd.cat" "%TMPCPYDIR%\setup"
copy "..\converted-sources-working-copy\drbd\drbd.inf" "%TMPCPYDIR%\setup"
copy "..\converted-sources-working-copy\crypto\linbit.cer"               "%TMPCPYDIR%\setup"
copy "c:\Ewdk\Program Files\Windows Kits\10\bin\x64\certmgr.exe"     "%TMPCPYDIR%\setup"

copy ".\etc\drbd.conf" "%TMPCPYDIR%\etc"
copy ".\etc\drbd.d\*.res" "%TMPCPYDIR%\etc\drbd.d"
copy ".\etc\drbd.d\*.conf" "%TMPCPYDIR%\etc\drbd.d"

copy ".\INSTALL-DRBD-admin.bat" "%TMPCPYDIR%"

rem RUNAS always asks for a password, unless credentials have already been saved via /SAVECRED
rem   runas /user:administrator      "%TMPCPYDIR%\INSTALL-DRBD-admin.bat"
rem so we're using PSEXEC instead
rem   https://technet.microsoft.com/en-us/sysinternals/bb897553
rem
rem windows-install\pstools\psexec  \\%computername% -i -h cmd.exe /c "%TMPCPYDIR%\INSTALL-DRBD-admin.bat"


if _%RUN_INST% == _yes goto inst

echo "--------------------------------------------------------------------"
echo "Please run "
echo      %TMPCPYDIR%\INSTALL-DRBD-admin.bat
echo "as an adminstrator
rem start explorer "%TMPCPYDIR%"
echo "--------------------------------------------------------------------"

rem We need some post-install hooks, don't do them for now.
goto exit

:inst
rem runas /user:administrator      "%0\..\INSTALL-DRBD-admin.bat"
"%TMPCPYDIR%\INSTALL-DRBD-admin.bat"
pause









xcopy /E /F /H /Y "src\git-complete\build\drbd\x86" "c:\program files (x86)\drbd\"
xcopy /E /F /H /Y "src\git-complete\build\drbd\x86" "c:\program files (x86)\drbd\"

xcopy /E /F /H /Y ".\src\git-complete\build\drbd\x86\Win7Debug" "c:\program files (x86)\drbd\inf\"
runas /user:administrator      "%0\..\INSTALL-DRBD-admin.bat"


rem %SystemRoot%\System32\InfDefaultInstall.exe ".\src\git-complete\build\drbd\x86\Win7Debug\bin\drbd.inf"

pause

:exit
