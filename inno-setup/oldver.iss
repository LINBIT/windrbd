function GetOldVersion: string;
var
	reg_path: string;
	version: String;
begin
	Result := '';
	
	reg_path := ExpandConstant('Software\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1');
	if not RegQueryStringValue(HKLM, reg_path, 'DisplayVersion', version) then begin
		if not RegQueryStringValue(HKCU, reg_path, 'DisplayVersion', version) then begin
			Result := '';
		end;
	end;
	Result := version;
end;

var myNeedRestart: Boolean;
    driverWasUnloaded: Boolean;

function NeedRestart: Boolean;
begin
	Result:= myNeedRestart and not driverWasUnloaded;
end;

function InitializeSetup: Boolean;
var
	version: String;
	str: String;
	buttons: Integer;

begin
	Result := True;
	version := GetOldVersion();
	myNeedRestart := False;
	driverWasUnloaded := False;
	if version <> '' then
	begin
		buttons := MB_YESNO;
		if version = '{#SetupSetting("AppVersion")}' then
			str := 'WinDRBD version '+version+' is already installed. It is not neccessary to install it again, unless you manually destroyed the WinDRBD installation. Do you wish to continue?'
		else
			str := ExpandConstant('Found WinDRBD version '+version+' installed. The version you are about to install is {#SetupSetting("AppVersion")}. You can safely install one over the other, however to restart the driver all WinDRBD resources are taken down by the installer. Optionally a reboot is required if the installed version is 1.0.0-rc16 or older. Continue?');

		if not WizardSilent then
		begin
			if MsgBox(str, mbConfirmation, buttons) = IDNO then
			begin
				MsgBox('Installation aborted.', mbInformation, MB_OK);
				Result := False;
			end;
		end;
		myNeedRestart := True;
	end;
end;
