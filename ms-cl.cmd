@echo off
@call %EWDK_BASE%/BuildEnv/SetupBuildEnv.cmd amd64
@cl.exe %*
