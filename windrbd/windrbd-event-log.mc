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
    Portuguese  = 0x0416:msg00001
    English     = 0x0409:msg00002
)

MessageId = 0x0001
Facility = DriverEntryLogs
Severity = Error
SymbolicName = EVT_HELLO_MESSAGE

Language = Portuguese
"Ola mundo!"
.

Language = English
"Hello world! test 123"
.


