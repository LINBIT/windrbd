Function DrbdAdm(Cmd, Res)
	Set shell = CreateObject("WScript.Shell")
' must be .exe else endless loop (restarts this script):
	Set p = shell.Exec("drbdadm.exe " + Cmd + " " + Res) 

	While p.Status = WshRunning
'		WScript.Sleep 50
		Sleep 50
	Wend

	if p.ExitCode <> 0 Then
		DrbdAdm = "Error"
	else
		DrbdAdm = p.stdout.readline
	end If
End Function

Select Case DrbdAdm("role", "w0")
	Case "Error"
		WScript.Echo "Error getting Role"
	Case "Primary"
		WScript.Echo "Is Primary"
	Case "Secondary"
		WScript.Echo "Is Secondary"
End Select

