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

function GetVersionCode: Integer;
Var s: String;
    v1, v2, v3: Integer;
    s1, s2, s3: String;
    i, pos1, pos2, pos3, pos4: Integer;
    R: Integer;

Begin
	s := GetOldVersion;
	if s = '' then
		Result := 0
	else
	try
		log('Old WinDRBD version is '+s);
		i := 1;
		pos1 := i;
		while (i <= Length(s)) and (s[i] <> '.') do
			i := i+1;

		i := i+1;
		pos2 := i;

		while (i <= Length(s)) and (s[i] <> '.') do
			i := i+1;
		i := i+1;
		pos3 := i;

		while (i <= Length(s)) and (s[i] <> '-') do
			i := i+1;
		pos4 := i;

		s1 := copy(s, pos1, pos2-pos1-1);
		s2 := copy(s, pos2, pos3-pos2-1);
		s3 := copy(s, pos3, pos4-pos3);

		v1 := StrToInt(s1);
		v2 := StrToInt(s2);
		v3 := StrToInt(s3);

		R := v1*256*256 + v2*256 + v3;
		Log(Format('WinDRBD version code is %x', [R]));
		Result := R;
	except
		Log('Some exception parsing version string '+s);
		Result := 0;
	end;
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
