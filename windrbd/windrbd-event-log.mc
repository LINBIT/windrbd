MessageIdTypedef = NTSTATUS

SeverityNames =
(
    Success         = 0x0:STATUS_SEVERITY_SUCCESS
    Informational   = 0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning         = 0x2:STATUS_SEVERITY_WARNING
    Error           = 0x3:STATUS_SEVERITY_ERROR
)

FacilityNames =
(
    System          = 0x0
    DriverEntryLogs = 0x2A:DRIVERENTRY_FACILITY_CODE
)

LanguageNames =
(
    English     = 0x0409:msg00002
)

MessageId = 0x0001
Facility = DriverEntryLogs
Severity = Informational
SymbolicName = WINDRBD_INFO_MESSAGE

Language = English
Info: %2
.

MessageId = 0x0001
Facility = DriverEntryLogs
Severity = Error
SymbolicName = WINDRBD_ERROR_MESSAGE

Language = English
Error: %2
.

