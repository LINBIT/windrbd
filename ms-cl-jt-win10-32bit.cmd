set EWDK_BASE=d:
call %EWDK_BASE%\BuildEnv\SetupBuildEnv.cmd x86
set PATH=%PATH%;"D:\Program Files\Microsoft Visual Studio\2017\BuildTools\VC\Tools\MSVC\14.14.26428\bin\Hostx64\x86"
cl.exe %*
