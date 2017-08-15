@echo off

rem This script currently just copies neccessary stuff to 
rem the Windows temp (%Temp%/drbd) directory. I am not sure
rem if we really need this step.
rem
rem @echo OFF

rem change drive, too...
cd /D ".\..\.."

rem .
rem The admin cannot access network drives;
rem the user cannot write to the "Program Files" directory.
rem There's no "ZIP" or "TAR", so we need to make a temporary copy.
rem .

set TMPCPYDIR="%Temp%\drbd"

mkdir "%TMPCPYDIR%"
mkdir "%TMPCPYDIR%\setup"

copy "converted-sources\drbd\drbd.sys" "%TMPCPYDIR%\setup"
copy "converted-sources\drbd\drbd.cat" "%TMPCPYDIR%\setup"
copy "converted-sources\drbd\drbd.inf" "%TMPCPYDIR%\setup"

copy "converted-sources\drbd\INSTALL-DRBD-admin.bat" "%TMPCPYDIR%"

rem RUNAS always asks for a password, unless credentials have already been saved via /SAVECRED
rem runas /user:administrator "%TMPCPYDIR%\INSTALL-DRBD-admin.bat"

echo Now, cd to %TMPCPYDIR% and execute INSTALL-DRBD-admin.bat as
echo the Adminitrator user (find cmd.exe in C:\Windows\System32
echo right click it (or Cmd click if your host is a Mac) and select
echo Run as Administrator)
echo ---
echo Then, Type
echo sc drbd start
echo to load the driver
echo ---
echo Note that you must disable Windows driver signature verification
echo on boot (for Windows 7, press F8 on boot and select Disable driver
echo signature verification (or so))
echo ---
echo Note also that Windows will refuse to boot once INSTALL-DRBD-admin.bat
echo is run because something is wrong in the INF file (most likely we're
echo just about to fix this) so *make a snapshot first*
