Dim a
a=MsgBox("A WinDRBD beta4 installation was found. We will uninstall it, since it conflicts with WinDRBD beta5 (and above) installations. The contents of your sysroot (C:\windrbd) will not be deleted. To complete the uninstall of WinDRBD beta4 you have to reboot the machine (sorry for that ...). Click yes to continue. Clicking no leaves the WinDRBD beta4 installation as it is.", vbYesNo, "WinDRBD beta 4 found")
WScript.Quit a
