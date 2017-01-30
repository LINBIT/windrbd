
rem set VC_BASE="%1"

call "../../../installs/ewdk/BuildEnv/SetupBuildEnv.cmd" amd64

date /t
time /t

rem VC := env PATH="$(PATH);$(VC_BASE)/../MSBuild/14.0/Bin" "$(VC_BASE)/VC/bin/cl.exe" 
rem

rem set VC_CL_PATH=z:\src\drbd-9\drbd\..\..\..\installs\ewdk\Program Files\Microsoft Visual Studio 14.0\..\MSBuild\14.0\Bin\x86_64\cl.exe
rem "%VC_CL_PATH%" %*
cl.exe %*
