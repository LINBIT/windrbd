#ifndef _WINDRBD_CONFIG_H
#define _WINDRBD_CONFIG_H

/* Windows (not ReactOS) target, with mingw */
// #ifndef REACTOS
#define CONFIG_HAVE_NETIO_DRIVER 1
// #endif

	/* TODO: also if not Server 2003: */
#ifndef REACTOS
#define CONFIG_HAVE_KERNEL_STACKSWAP_ENABLE 1
#define CONFIG_HAVE_NO_EXECUTE 1
#endif

/* Those need to be implemented: */
// #define CONFIG_HAVE_IO_CREATE_DEVICE_SECURE 1
// #define CONFIG_HAVE_RW_LOCKS 1


/* Currently only works on 32 bit platforms, working on 64 bit: */
#ifdef CONFIG_32BIT
#define CONFIG_HAVE_SEH2 1
#endif

#ifdef CONFIG_HAVE_NO_EXECUTE
	/* Windows >= Windows 8 */
	/* TODO: this should move somewhere else: */
#define NonPagedPoolNx 512
#define WinDRBDNonPagedPool NonPagedPoolNx
#else
	/* ReactOS, Windows < Windows 8 (for example Server 2003) */
#define WinDRBDNonPagedPool NonPagedPool
#endif

#endif
