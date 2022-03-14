set EWDK_BASE=e:
call %EWDK_BASE%\BuildEnv\SetupBuildEnv.cmd amd64
set PATH=%PATH%;"E:\Program Files\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.28.29910\bin\Hostx64\x64"
cl.exe %*
