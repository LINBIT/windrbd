#ifndef _NET_IPV6_H
#define _NET_IPV6_H

#include <linux/types.h>
#include <asm/byteorder.h>

	/* Opaque type. Definition in ReactOS differs from Linux
	 * definition. See psdk/in6addr.h in the ReactOS headers.
	 */
struct in6_addr;

struct in6_addr_linux {
	union {
		__u8		u6_addr8[16];
		__be16		u6_addr16[8];
		__be32		u6_addr32[4];
	} in6_u;
};

#define IPV6_ADDR_ANY		0x0000U

#define IPV6_ADDR_UNICAST	0x0001U
#define IPV6_ADDR_MULTICAST	0x0002U

#define IPV6_ADDR_LOOPBACK	0x0010U
#define IPV6_ADDR_LINKLOCAL	0x0020U
#define IPV6_ADDR_SITELOCAL	0x0040U

#define IPV6_ADDR_COMPATv4	0x0080U

#define IPV6_ADDR_SCOPE_MASK	0x00f0U

#define IPV6_ADDR_MAPPED	0x1000U

static inline bool ipv6_addr_equal(const struct in6_addr *wa1,
				   const struct in6_addr *wa2)
{
	const struct in6_addr_linux *a1 = (struct in6_addr_linux*) wa1;
	const struct in6_addr_linux *a2 = (struct in6_addr_linux*) wa2;

	return ((a1->in6_u.u6_addr32[0] ^ a2->in6_u.u6_addr32[0]) |
		(a1->in6_u.u6_addr32[1] ^ a2->in6_u.u6_addr32[1]) |
		(a1->in6_u.u6_addr32[2] ^ a2->in6_u.u6_addr32[2]) |
		(a1->in6_u.u6_addr32[3] ^ a2->in6_u.u6_addr32[3])) == 0;
}

	/* Only check for LINKLOCAL which is needed in DRBD */
static inline int ipv6_addr_type(const struct in6_addr *waddr)
{
	const struct in6_addr_linux *addr = (struct in6_addr_linux*) waddr;
	__be32 st;

	st = addr->in6_u.u6_addr32[0];

	if ((st & htonl(0xFFC00000)) == htonl(0xFE800000))
		return IPV6_ADDR_LINKLOCAL;

	return 0;
}

#endif

