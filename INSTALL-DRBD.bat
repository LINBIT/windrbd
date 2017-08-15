rem Adjust these variables to match your system

set CYGWINDIR="c:\cygwin64"
rem Probably not needed .. we work without driver signing
set CERTMGR="c:\Ewdk\Program Files\Windows Kits\10\bin\x64\certmgr.exe"
rem This script currently just copies neccessary stuff to 
rem the Windows temp (%Temp%/drbd) directory. I am not sure
rem if we really need this step.
rem
rem @echo OFF

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

copy "%0\..\..\drbd-utils\user\v9\*.exe" "%TMPCPYDIR%\bin"
rem You need to change this to the location of cygwin on your system.
copy "%CYGWINDIR%\bin\cygwin1.dll" "%TMPCPYDIR%\bin"

copy "..\converted-sources-working-copy\drbd\drbd.sys" "%TMPCPYDIR%\setup"
copy "..\converted-sources-working-copy\drbd\drbd.cat" "%TMPCPYDIR%\setup"
copy "..\converted-sources-working-copy\drbd\drbd.inf" "%TMPCPYDIR%\setup"
copy "..\converted-sources-working-copy\crypto\linbit.cer"               "%TMPCPYDIR%\setup"
rem You need to change this to the location of Ewdk on your system.
copy "     "%TMPCPYDIR%\setup"

copy ".\etc\drbd.conf" "%TMPCPYDIR%\etc"
copy ".\etc\drbd.d\*.res" "%TMPCPYDIR%\etc\drbd.d"
copy ".\etc\drbd.d\*.conf" "%TMPCPYDIR%\etc\drbd.d"

copy ".\INSTALL-DRBD-admin.bat" "%TMPCPYDIR%"

rem RUNAS always asks for a password, unless credentials have already been saved via /SAVECRED
runas /user:administrator "%TMPCPYDIR%\INSTALL-DRBD-admin.bat"

echo "Type"
echo "sc drbd start"
echo "to load the driver"
echo
echo "Note that you must disable Windows driver signature verification"
echo "on boot (for Windows 7, press F8 on boot and select Disable driver"
echo "signature verification (or so))"
