@echo off
@call %EWDK_BASE%\BuildEnv\SetupBuildEnv.cmd amd64
"%EWDK_BASE%\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.31.31103\bin\Hostx64\x64\cl.exe" %*
