#include <wdm.h>

HANDLE OpenSerialPort(void)
{
    OBJECT_ATTRIBUTES Attr;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    ULONG ShareAccess;
    static HANDLE Handle;
    UNICODE_STRING FileName;

    if (Handle != NULL)
        return Handle;

    ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
    RtlInitUnicodeString(&FileName, L"\\DosDevices\\COM2");

    InitializeObjectAttributes(&Attr,                   /* Attribute buffer */
                               &FileName,               /* Device name */
                               OBJ_CASE_INSENSITIVE |   /* Attributes */
                               OBJ_KERNEL_HANDLE,
                               NULL,                    /* Root directory */
                               NULL);                   /* Security descriptor */

    Handle = NULL;
    Status = ZwCreateFile(&Handle,                               /* Return file handle */
                          GENERIC_READ | GENERIC_WRITE,         /* Desired access */
                          &Attr,                                /* Object attributes */
                          &Iosb,                                /* IO status */
                          0,                                    /* Initial allocation size */
                          FILE_ATTRIBUTE_NORMAL,                /* File attributes */
                          ShareAccess,                          /* Share access */
                          FILE_OPEN,                         /* Create disposition */
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,                                    /* Create options */
                          NULL,                                 /* EA buffer */
                          0);                                   /* EA length */

    DbgPrint("ZwCreateFile returned %08x\n", Status);
    return Handle;
}

void WriteSerial(char *buf, size_t length)
{
    HANDLE ComPort = OpenSerialPort();
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;

    if (ComPort != NULL) {
        status = ZwWriteFile(ComPort, NULL, NULL, NULL, &iosb, buf, length, NULL, NULL);
        DbgPrint("ZwWriteFile returned %08x\n", status);
    }
}

void WriteStringSerial(char *buf)
{
    WriteSerial(buf, strlen(buf));
}

