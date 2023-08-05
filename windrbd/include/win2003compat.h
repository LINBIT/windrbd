#ifndef _WIN2003SUPPORT_
#define _WIN2003SUPPORT_

	/* This just contains some typedefs missing before Windows
	 * Server 2008.
	 */

#if (NTDDI_VERSION < 0x06000000)
typedef unsigned short u_short;
struct _WSACMSGHDR;
typedef struct _WSACMSGHDR CMSGHDR, *PCMSGHDR;
#endif

typedef unsigned short *PZZWSTR;

#endif

