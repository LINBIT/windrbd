#ifndef _WINDRBD_CONFIG_H
#define _WINDRBD_CONFIG_H

#ifndef REACTOS
#define CONFIG_HAVE_NETIO_DRIVER 1
#endif
/* Else Windows (not ReactOS) target, with mingw */

// #define CONFIG_HAVE_IO_CREATE_DEVICE_SECURE 1
// #define CONFIG_HAVE_RW_LOCKS 1
// #define CONFIG_HAVE_NO_EXECUTE 1
// #define CONFIG_HAVE_TRY 1

#endif
