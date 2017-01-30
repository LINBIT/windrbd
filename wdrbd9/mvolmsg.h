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


//
// Define the severity codes
//


//
// MessageId: MSG_DRIVER_LOAD
//
// MessageText:
//
// Driver is loading successfully.
//
#define MSG_DRIVER_LOAD                  0x40001389L

//
// MessageId: MSG_NO_JOB
//
// MessageText:
//
// No Job on %2.
//
#define MSG_NO_JOB                       0xC000138AL

//
// MessageId: MSG_FIND_JOB_ERROR
//
// MessageText:
//
// cannot find same job on %2.
//
#define MSG_FIND_JOB_ERROR               0xC000138BL

//
// MessageId: MSG_INSUFFICIENT_RESOURCES
//
// MessageText:
//
// insufficient resources on %2.
//
#define MSG_INSUFFICIENT_RESOURCES       0xC000138CL

//
// MessageId: MSG_WRITE_ERROR
//
// MessageText:
//
// cannot write to %2.
//
#define MSG_WRITE_ERROR                  0xC000138DL

//
// MessageId: MSG_BUFFER_SMALL
//
// MessageText:
//
// Buffer too small on %2.
//
#define MSG_BUFFER_SMALL                 0xC000138EL

//
// MessageId: MSG_ROOT_DEVICE_REQUEST
//
// MessageText:
//
// invalid Root Device Request.
//
#define MSG_ROOT_DEVICE_REQUEST          0xC000138FL

//
// MessageId: MSG_NO_DEVICE
//
// MessageText:
//
// cannot find volume, %2.
//
#define MSG_NO_DEVICE                    0xC0001390L

//
// MessageId: MSG_INVALID_DEVICE_REQUEST
//
// MessageText:
//
// invalid request on %2.
//
#define MSG_INVALID_DEVICE_REQUEST       0xC0001391L

//
// MessageId: MSG_THREAD_INIT_ERROR
//
// MessageText:
//
// cannot create thread on %2.
//
#define MSG_THREAD_INIT_ERROR            0xC0001392L

//
// MessageId: MSG_EVENT_INIT_ERROR
//
// MessageText:
//
// cannot create event on %2.
//
#define MSG_EVENT_INIT_ERROR             0xC0001393L

//
// MessageId: MSG_ADD_DEVICE_ERROR
//
// MessageText:
//
// cannot add device.
//
#define MSG_ADD_DEVICE_ERROR             0xC0001394L

//
// MessageId: MSG_CALL_DRIVER_ERROR
//
// MessageText:
//
// cannot process request on %2.
//
#define MSG_CALL_DRIVER_ERROR            0xC0001395L

//
// MessageId: MSG_INVALID_MJ
//
// MessageText:
//
// invalid Major Function on %2.
//
#define MSG_INVALID_MJ                   0xC0001396L

//
// MessageId: MSG_INVALID_PARAMETER
//
// MessageText:
//
// invalid parameters on %2.
//
#define MSG_INVALID_PARAMETER            0xC0001397L

//
// MessageId: MSG_MAKE_JOB_ERROR
//
// MessageText:
//
// cannot make job on %2.
//
#define MSG_MAKE_JOB_ERROR               0xC0001398L

//
// MessageId: MSG_JOB_TIMEOUT
//
// MessageText:
//
// job timeout occured on %2.
//
#define MSG_JOB_TIMEOUT                  0xC0001399L

//
// MessageId: MSG_DEVICE_BUSY
//
// MessageText:
//
// Device is busy on %2.
//
#define MSG_DEVICE_BUSY                  0xC000139AL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//
// MessageId: DEV_ERR_3001
//
// MessageText:
//
// %2 ASSERTION FAILED in file:%3 line:%4.
//
#define DEV_ERR_3001                     0xC0000BB9L

//
// MessageId: DEV_ERR_3002
//
// MessageText:
//
// %2 Logic failure at file:%3 func:%4 line:%5.
//
#define DEV_ERR_3002                     0xC0000BBAL

//
// MessageId: DEV_ERR_3003
//
// MessageText:
//
// DRBD_PANIC: %2.
//
#define DEV_ERR_3003                     0xC0000BBBL

//
// MessageId: DEV_ERR_3005
//
// MessageText:
//
// %2.
//
#define DEV_ERR_3005                     0xC0000BBDL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//
// MessageId: CONN_EMERG
//
// MessageText:
//
// <0>d-con %2
//
#define CONN_EMERG                       0xC0002EE1L

//
// MessageId: CONN_ALERT
//
// MessageText:
//
// <1>d-con %2
//
#define CONN_ALERT                       0x80002EE2L

//
// MessageId: CONN_CRIT
//
// MessageText:
//
// <2>d-con %2
//
#define CONN_CRIT                        0xC0002EE3L

//
// MessageId: CONN_ERR
//
// MessageText:
//
// <3>d-con %2
//
#define CONN_ERR                         0xC0002EE4L

//
// MessageId: CONN_WARN
//
// MessageText:
//
// <4>d-con %2
//
#define CONN_WARN                        0x80002EE5L

//
// MessageId: CONN_NOTICE
//
// MessageText:
//
// <5>d-con %2
//
#define CONN_NOTICE                      0x40002EE6L

//
// MessageId: CONN_INFO
//
// MessageText:
//
// <6>d-con %2
//
#define CONN_INFO                        0x40002EE7L

//
// MessageId: CONN_DBG
//
// MessageText:
//
// <7>d-con %2
//
#define CONN_DBG                         0x40002EE8L

//
// MessageId: DEV_EMERG
//
// MessageText:
//
// <0>block drbd%2
//
#define DEV_EMERG                        0xC0002EEBL

//
// MessageId: DEV_ALERT
//
// MessageText:
//
// <1>block drbd%2
//
#define DEV_ALERT                        0x80002EECL

//
// MessageId: DEV_CRIT
//
// MessageText:
//
// <2>block drbd%2
//
#define DEV_CRIT                         0xC0002EEDL

//
// MessageId: DEV_ERR
//
// MessageText:
//
// <3>block drbd%2
//
#define DEV_ERR                          0xC0002EEEL

//
// MessageId: DEV_WARN
//
// MessageText:
//
// <4>block drbd%2
//
#define DEV_WARN                         0x80002EEFL

//
// MessageId: DEV_NOTICE
//
// MessageText:
//
// <5>block drbd%2
//
#define DEV_NOTICE                       0x40002EF0L

//
// MessageId: DEV_INFO
//
// MessageText:
//
// <6>block drbd%2
//
#define DEV_INFO                         0x40002EF1L

//
// MessageId: DEV_DBG
//
// MessageText:
//
// <7>block drbd%2
//
#define DEV_DBG                          0x40002EF2L

//
// MessageId: PRINTK_EMERG
//
// MessageText:
//
// <0>%2
//
#define PRINTK_EMERG                     0xC0002EF5L

//
// MessageId: PRINTK_ALERT
//
// MessageText:
//
// <1>%2
//
#define PRINTK_ALERT                     0x80002EF6L

//
// MessageId: PRINTK_CRIT
//
// MessageText:
//
// <2>%2
//
#define PRINTK_CRIT                      0xC0002EF7L

//
// MessageId: PRINTK_ERR
//
// MessageText:
//
// <3>%2
//
#define PRINTK_ERR                       0xC0002EF8L

//
// MessageId: PRINTK_WARN
//
// MessageText:
//
// <4>%2
//
#define PRINTK_WARN                      0x80002EF9L

//
// MessageId: PRINTK_NOTICE
//
// MessageText:
//
// <5>%2
//
#define PRINTK_NOTICE                    0x40002EFAL

//
// MessageId: PRINTK_INFO
//
// MessageText:
//
// <6>%2
//
#define PRINTK_INFO                      0x40002EFBL

//
// MessageId: PRINTK_DBG
//
// MessageText:
//
// <7>%2
//
#define PRINTK_DBG                       0x40002EFCL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//
// MessageId: MSG_CLI_EMERG
//
// MessageText:
//
// <Emerge>CLI %2
//
#define MSG_CLI_EMERG                    0xC0003A99L

//
// MessageId: MSG_CLI_ALERT
//
// MessageText:
//
// <Alert>CLI %2
//
#define MSG_CLI_ALERT                    0xC0003A9AL

//
// MessageId: MSG_CLI_CRITICAL
//
// MessageText:
//
// <Critical>CLI %2
//
#define MSG_CLI_CRITICAL                 0xC0003A9BL

//
// MessageId: MSG_CLI_ERROR
//
// MessageText:
//
// <Error>CLI %2
//
#define MSG_CLI_ERROR                    0xC0003A9CL

//
// MessageId: MSG_CLI_WARNING
//
// MessageText:
//
// <Warning>CLI %2
//
#define MSG_CLI_WARNING                  0x80003A9DL

//
// MessageId: MSG_CLI_NOTICE
//
// MessageText:
//
// <Notice>CLI %2
//
#define MSG_CLI_NOTICE                   0x80003A9EL

//
// MessageId: MSG_CLI_INFO
//
// MessageText:
//
// <Infomation>CLI %2
//
#define MSG_CLI_INFO                     0x40003A9FL

//
// MessageId: MSG_CLI_SUCCESS
//
// MessageText:
//
// <Success>CLI %2
//
#define MSG_CLI_SUCCESS                  0x00003AA0L

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
