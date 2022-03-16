set EWDK_BASE=e:
call %EWDK_BASE%\BuildEnv\SetupBuildEnv.cmd amd64
set PATH=%PATH%;"D:\Program Files\Microsoft Visual Studio\2017\BuildTools\VC\Tools\MSVC\14.14.26428\bin\Hostx64\x64"
cl.exe %*
