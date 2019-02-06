' TODO: later parameter
Dim DrbdResource
DrbdResource = "w0"

Function DrbdAdm(Cmd, Res)
	Set shell = CreateObject("WScript.Shell")
' must be .exe else endless loop (restarts this script):
	Set p = shell.Exec("drbdadm.exe " + Cmd + " " + Res) 

	While p.Status = WshRunning
		WScript.Sleep 50
	Wend

	if p.ExitCode <> 0 Then
		Resource.LogError "drbdadm " + cmd + " " + res + " failed"
		Resource.LogError p.stderr.readall
' not sure about drbdadm's behaviour ...
		Resource.LogError p.stdout.readall

		DrbdAdm = "Error"
	else
		DrbdAdm = p.stdout.readline
	end If
End Function

' Sample usage:
' 
' Select Case DrbdAdm("role", "w0")
' 	Case "Error"
' 		WScript.Echo "Error getting Role"
' 	Case "Primary"
' 		WScript.Echo "Is Primary"
' 	Case "Secondary"
' 		WScript.Echo "Is Secondary"
' End Select

' Handlers called by cluster manager
' Return Value: 0 .. ok 1 .. error
Function Open()
	Resource.LogInformation "Open called"
	Open = 0
End Function

Function Online()
	Resource.LogInformation "Online called"

	if DrbdAdm("up", DrbdResource) = "Error" then
		Online = 1
	elseif DrbdAdm("primary", DrbdResource) = "Error" then
		Online = 1
	else
		Online = 0
	end if
End Function

Function Offline()
	Resource.LogInformation "Offline called"

	if DrbdAdm("down", DrbdResource) = "Error" then
		Offline = 1
	else
		Offline = 0
	end if
End Function

Function LooksAlive()
	Resource.LogInformation "LooksAlive called"
	if DrbdAdm("role", "w0") = "Primary" Then
		LooksAlive = 0
	else
		LooksAlive = 1
	end if
End Function

Function IsAlive()
	Resource.LogInformation "IsAlive called"
	IsAlive = LooksAlive
End Function

Function Terminate()
	Resource.LogInformation "Terminate called"
	Terminate = 0
End Function

Function Close()
	Resource.LogInformation "Close called"
	Close = 0
End Function
