#ifndef _UAPI_LINUX_TCP_H
#define _UAPI_LINUX_TCP_H

#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */

#endif
