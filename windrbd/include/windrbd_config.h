#ifndef _WINDRBD_CONFIG_H
#define _WINDRBD_CONFIG_H

/* Windows (not ReactOS) target, with mingw */
/* Update: Now we wrote our NETIO.SYS driver for ReactOS and Windows Server
 * 2003. So always enable network:: */
#define CONFIG_HAVE_NETIO_DRIVER 1

#ifdef CONFIG_64BIT
#define CONFIG_HAVE_KERNEL_STACKSWAP_ENABLE 1
#define CONFIG_HAVE_NO_EXECUTE 1
#endif

/* Those need to be implemented: */
// #define CONFIG_HAVE_IO_CREATE_DEVICE_SECURE 1
	/* Windows Server 2016 and later */
#ifdef CONFIG_64BIT
#define CONFIG_HAVE_RW_LOCKS 1
#endif

/* Currently only works on 32 bit platforms, working on 64 bit: */
#ifdef CONFIG_32BIT
#define CONFIG_HAVE_SEH2 1
#endif

#ifdef CONFIG_HAVE_NO_EXECUTE
	/* Windows >= Windows 8 */
	/* TODO: this should move somewhere else: */
#define NonPagedPoolNx 512
#define WinDRBDNonPagedPool NonPagedPoolNx
#define MdlMappingNoExecute     0x40000000  // Create the mapping as noexecute
#define WinDRBDMdlMappingNoExecute MdlMappingNoExecute
#else
	/* ReactOS, Windows < Windows 8 (for example Server 2003) */
#define WinDRBDNonPagedPool NonPagedPool
#define WinDRBDMdlMappingNoExecute 0

#endif

#endif
