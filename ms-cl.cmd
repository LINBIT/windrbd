@echo off
@call "../../../installs/ewdk/BuildEnv/SetupBuildEnv.cmd" amd64
@cl.exe %*
