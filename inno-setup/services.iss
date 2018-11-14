#include "service-library.iss"

function MyStopService(SvcName: String): boolean;
var
  S: Longword;
begin
  Result := False;
  if ServiceExists(SvcName) then begin
    S:= SimpleQueryService(SvcName);
    if S <> SERVICE_STOPPED then begin
      SimpleStopService(SvcName, True, False);
      Result := True;
    end;
  end;
end;

procedure MyStartService(SvcName: String);
begin
   if ServiceExists(SvcName) then begin
     SimpleStartService(SvcName, True, False);
   end;
end;

