//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define DRIVERENTRY_FACILITY_CODE        0x2A


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: WINDRBD_SUCCESS_MESSAGE
//
// MessageText:
//
// Success: %2
//
#define WINDRBD_SUCCESS_MESSAGE          ((NTSTATUS)0x002A0001L)

//
// MessageId: WINDRBD_INFO_MESSAGE
//
// MessageText:
//
// Info: %2
//
#define WINDRBD_INFO_MESSAGE             ((NTSTATUS)0x402A0001L)

//
// MessageId: WINDRBD_WARNING_MESSAGE
//
// MessageText:
//
// Warning: %2
//
#define WINDRBD_WARNING_MESSAGE          ((NTSTATUS)0x802A0001L)

//
// MessageId: WINDRBD_ERROR_MESSAGE
//
// MessageText:
//
// Error: %2
//
#define WINDRBD_ERROR_MESSAGE            ((NTSTATUS)0xC02A0001L)

