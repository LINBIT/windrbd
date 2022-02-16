@echo off
@call %EWDK_BASE%\BuildEnv\SetupBuildEnv.cmd x86
@cl.exe %*
