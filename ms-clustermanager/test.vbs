' Return Value: 0 .. ok 1 .. error
Function Open()
'	MsgBox "Hallo Open", vbOk, "Hallo"
	Resource.LogInformation "Hallo Open"
	Open = 0
End Function

Function Online()
'	MsgBox "Hallo Online", vbOk, "Hallo"
	Resource.LogInformation "Hallo Online"
	Online = 0
End Function

Function Offline()
'	MsgBox "Hallo Offline", vbOk, "Hallo"
	Resource.LogInformation "Hallo Offline"
	Offline = 0
End Function

Function LooksAlive()
'	MsgBox "Hallo LooksAlive", vbOk, "Hallo"
	Resource.LogInformation "Hallo LooksAlive"
	LooksAlive = 0
End Function

Function IsAlive()
'	MsgBox "Hallo IsAlive", vbOk, "Hallo"
	Resource.LogInformation "Hallo IsAlive"
	IsAlive = 0
End Function

Function Terminate()
'	MsgBox "Hallo Terminate", vbOk, "Hallo"
	Resource.LogInformation "Hallo Terminate"
	Terminate = 0
End Function

Function Close()
'	MsgBox "Hallo Close", vbOk, "Hallo"
	Resource.LogInformation "Hallo Close"
	Close = 0
End Function

' MsgBox "Hallo Main", vbOk,  "Hallo"

