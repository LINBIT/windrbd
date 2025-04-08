#ifndef _WINDRBD_CONFIG_H
#define _WINDRBD_CONFIG_H

#ifndef WINNT_52
#define CONFIG_HAVE_KERNEL_STACKSWAP_ENABLE 1
#define CONFIG_HAVE_NO_EXECUTE 1
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
