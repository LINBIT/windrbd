﻿#ifndef __DRBD_WINGENL_H__
#define __DRBD_WINGENL_H__
#include <wdm.h>
#include <wsk.h>
#include <linux/list.h>
#if 0
#include "windows/wingenl.h"
#endif
#include "drbd_windows.h"

struct sk_buff
{
    int len;
		/* Maybe TODO: In current Linux versions these are
		 * pointers into the data buffer.
		 */

    unsigned int tail;
    unsigned int end;

    unsigned char data[1];
};

static __inline int skb_is_nonlinear(const struct sk_buff *skb)
{
	return skb->len;
}

static __inline unsigned char *skb_tail_pointer(const struct sk_buff *skb)
{
	return (unsigned char*)((size_t)skb->data + (size_t) skb->tail);
}

/**
 *	skb_tailroom - bytes at buffer end
 *	@skb: buffer to check
 *
 *	Return the number of bytes of free space at the tail of an sk_buff
 */
static __inline int skb_tailroom(const struct sk_buff *skb)
{
	return skb->end - skb->tail;
}

struct netlink_callback
{
    struct sk_buff          *skb;
    const struct nlmsghdr   *nlh;
    ULONG_PTR               args[6];
};


struct genl_info;
struct genl_ops
{
    u8    cmd;
    unsigned int		flags;
    const struct nla_policy	*policy;
    int (*doit)(struct sk_buff *skb, struct genl_info *info);
    int (*dumpit)(struct sk_buff *skb, struct netlink_callback *cb);
    int (*done)(struct netlink_callback *cb);
};

#ifndef __read_mostly
#define __read_mostly
#endif

#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)

/**
* struct genl_family - generic netlink family
* @id: protocol family idenfitier
* @hdrsize: length of user specific header in bytes
* @name: name of family
* @version: protocol version
* @maxattr: maximum number of attributes supported
* @attrbuf: buffer to store parsed attributes
* @ops_list: list of all assigned operations
* @family_list: family list
* @mcast_groups: multicast groups list
*/
struct genl_family
{
    unsigned int		id;
    unsigned int		hdrsize;
    char			name[GENL_NAMSIZ];
    unsigned int		version;
    unsigned int		maxattr;
    struct nlattr **	attrbuf;	/* private */
    struct list_head	ops_list;	/* private */
    struct list_head	family_list;	/* private */
    struct list_head	mcast_groups;	/* private */
};

/**
* struct genl_info - receiving information
* @snd_seq: sending sequence number
* @nlhdr: netlink message header
* @genlhdr: generic netlink message header
* @userhdr: user specific header
* @attrs: netlink attributes
*/
struct genl_info
{
    __u32			seq;
    struct nlmsghdr *	nlhdr;
    struct genlmsghdr *	genlhdr;
    void *			userhdr;
    struct nlattr **	attrs;
    u32             snd_seq;
    u32			    snd_portid;
	/* those two will go away */
    PWSK_SOCKET		NetlinkSock;
    LIST_ENTRY      ListEntry;

	int is_ioctl_packet;	/* will also go away */

};

/**
* Standard attribute types to specify validation policy
*/
enum
{
    NLA_UNSPEC,
    NLA_U8,
    NLA_U16,
    NLA_U32,
    NLA_U64,
    NLA_STRING,
    NLA_FLAG,
    NLA_MSECS,
    NLA_NESTED,
    NLA_NESTED_COMPAT,
    NLA_NUL_STRING,
    NLA_BINARY,
    __NLA_TYPE_MAX,
};

#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

/**
* struct nla_policy - attribute validation policy
* @type: Type of attribute or NLA_UNSPEC
* @len: Type specific length of payload
*
* Policies are defined as arrays of this struct, the array must be
* accessible by attribute type up to the highest identifier to be expected.
*
* Meaning of `len' field:
*    NLA_STRING           Maximum length of string
*    NLA_NUL_STRING       Maximum length of string (excluding NUL)
*    NLA_FLAG             Unused
*    NLA_BINARY           Maximum length of attribute payload
*    NLA_NESTED_COMPAT    Exact length of structure payload
*    All other            Exact length of attribute payload
*
* Example:
* static struct nla_policy my_policy[ATTR_MAX+1] __read_mostly = {
* 	[ATTR_FOO] = { .type = NLA_U16 },
*	[ATTR_BAR] = { .type = NLA_STRING, .len = BARSIZ },
*	[ATTR_BAZ] = { .len = sizeof(struct mystruct) },
* };
*/
struct nla_policy
{
    __u16		type;
    __u16		len;
};

extern int		nla_validate(struct nlattr *head, int len, int maxtype,
    const struct nla_policy *policy);
extern int		nla_parse(struct nlattr *tb[], int maxtype,
struct nlattr *head, int len,
    const struct nla_policy *policy);
extern int		nla_policy_len(const struct nla_policy *, int);
extern struct nlattr *	nla_find(struct nlattr *head, int len, int attrtype);
extern size_t		nla_strlcpy(char *dst, const struct nlattr *nla,
    size_t dstsize);
extern int		nla_memcpy(void *dest, const struct nlattr *src, int count);
extern int		nla_memcmp(const struct nlattr *nla, const void *data,
    size_t size);
extern int		nla_strcmp(const struct nlattr *nla, const char *str);
extern struct nlattr *	__nla_reserve(struct sk_buff *msg, int attrtype,
    int attrlen);
extern void *		__nla_reserve_nohdr(struct sk_buff *msg, int attrlen);
extern struct nlattr *	nla_reserve(struct sk_buff *msg, int attrtype,
    int attrlen);
extern void *		nla_reserve_nohdr(struct sk_buff *msg, int attrlen);
extern void		__nla_put(struct sk_buff *msg, int attrtype,
    int attrlen, const void *data);
extern void		__nla_put_nohdr(struct sk_buff *msg, int attrlen,
    const void *data);
extern int		nla_put(struct sk_buff *msg, int attrtype,
    int attrlen, const void *data);
extern int		nla_put_nohdr(struct sk_buff *msg, int attrlen,
    const void *data);
extern int		nla_append(struct sk_buff *msg, int attrlen,
    const void *data);

/**************************************************************************
* Netlink Messages
**************************************************************************/

/**
* nlmsg_msg_size - length of netlink message not including padding
* @payload: length of message payload
*/
static __inline u16 nlmsg_msg_size(u16 payload)
{
    return NLMSG_HDRLEN + payload;
}

/**
* nlmsg_total_size - length of netlink message including padding
* @payload: length of message payload
*/
static __inline u16 nlmsg_total_size(u16 payload)
{
    return NLMSG_ALIGN(nlmsg_msg_size(payload));
}

/**
* nlmsg_padlen - length of padding at the message's tail
* @payload: length of message payload
*/
static __inline u16 nlmsg_padlen(u16 payload)
{
    return nlmsg_total_size(payload) - nlmsg_msg_size(payload);
}

/**
* nlmsg_data - head of message payload
* @nlh: netlink messsage header
*/
static __inline void *nlmsg_data(const struct nlmsghdr *nlh)
{
    return (unsigned char *)nlh + NLMSG_HDRLEN;
}

/**
* nlmsg_len - length of message payload
* @nlh: netlink message header
*/
static __inline int nlmsg_len(const struct nlmsghdr *nlh)
{
    return nlh->nlmsg_len - NLMSG_HDRLEN;
}

/**
* nlmsg_attrdata - head of attributes data
* @nlh: netlink message header
* @hdrlen: length of family specific header
*/
static __inline struct nlattr *nlmsg_attrdata(const struct nlmsghdr *nlh,
    int hdrlen)
{
    unsigned char *data = nlmsg_data(nlh);
    return (struct nlattr *) (data + NLMSG_ALIGN(hdrlen));
}

/**
* nlmsg_attrlen - length of attributes data
* @nlh: netlink message header
* @hdrlen: length of family specific header
*/
static __inline int nlmsg_attrlen(const struct nlmsghdr *nlh, int hdrlen)
{
    return nlmsg_len(nlh) - NLMSG_ALIGN(hdrlen);
}

/**
* nlmsg_ok - check if the netlink message fits into the remaining bytes
* @nlh: netlink message header
* @remaining: number of bytes remaining in message stream
*/
static __inline int nlmsg_ok(const struct nlmsghdr *nlh, int remaining)
{
    return (remaining >= (int) sizeof(struct nlmsghdr) &&
        nlh->nlmsg_len >= sizeof(struct nlmsghdr) &&
        nlh->nlmsg_len <= (__u32)remaining);
}

extern void nlmsg_free(struct sk_buff *skb);

/**
* nlmsg_trim - shorten socket buffer skb to end at position pointed to
	       by mark.
* @skb: socket buffer
* @mark: pointer in skb->data where buffer should end
*/
static __inline void nlmsg_trim(struct sk_buff *skb, const void *mark)
{
	if (mark) {
		size_t len = ((const unsigned char*)mark) - skb->data;
		if (len < skb->len) {
			skb->len = len;
			skb->tail = len;
		}
	}
}

/**************************************************************************
* Netlink Attributes
**************************************************************************/

/**
* nla_attr_size - length of attribute not including padding
* @payload: length of payload
*/
static __inline int nla_attr_size(int payload)
{
    return NLA_HDRLEN + payload;
}

/**
* nla_total_size - total length of attribute including padding
* @payload: length of payload
*/
static __inline int nla_total_size(int payload)
{
    return NLA_ALIGN(nla_attr_size(payload));
}

/**
* nla_padlen - length of padding at the tail of attribute
* @payload: length of payload
*/
static __inline int nla_padlen(int payload)
{
    return nla_total_size(payload) - nla_attr_size(payload);
}

#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK ~0
#endif

/**
* nla_type - attribute type
* @nla: netlink attribute
*/
static __inline int nla_type(const struct nlattr *nla)
{
    return nla->nla_type & NLA_TYPE_MASK;
}

/**
* nla_data - head of payload
* @nla: netlink attribute
*/
static __inline void *nla_data(const struct nlattr *nla)
{
    return (char *)nla + NLA_HDRLEN;
}


/**
* nla_len - length of payload
* @nla: netlink attribute
*/

static __inline int nla_len(const struct nlattr *nla)
{
    return nla->nla_len - NLA_HDRLEN;
}

//#endif
/**
* nla_ok - check if the netlink attribute fits into the remaining bytes
* @nla: netlink attribute
* @remaining: number of bytes remaining in attribute stream
*/
static __inline int nla_ok(const struct nlattr *nla, int remaining)
{
    return remaining >= (int) sizeof(*nla) &&
        nla->nla_len >= sizeof(*nla) &&
        nla->nla_len <= remaining;
}

/**
* nla_next - next netlink attribute in attribute stream
* @nla: netlink attribute
* @remaining: number of bytes remaining in attribute stream
*
* Returns the next netlink attribute in the attribute stream and
* decrements remaining by the size of the current attribute.
*/
static __inline struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
    int totlen = NLA_ALIGN(nla->nla_len);

    *remaining -= totlen;
    return (struct nlattr *) ((char *)nla + totlen);
}

/**
* nla_find_nested - find attribute in a set of nested attributes
* @nla: attribute containing the nested attributes
* @attrtype: type of attribute to look for
*
* Returns the first attribute which matches the specified type.
*/
static __inline struct nlattr *nla_find_nested(struct nlattr *nla, int attrtype)
{
    return nla_find(nla_data(nla), nla_len(nla), attrtype);
}

/**
* nla_parse_nested - parse nested attributes
* @tb: destination array with maxtype+1 elements
* @maxtype: maximum attribute type to be expected
* @nla: attribute containing the nested attributes
* @policy: validation policy
*
* See nla_parse()
*/
static __inline int nla_parse_nested(struct nlattr *tb[], int maxtype,
    const struct nlattr *nla,
    const struct nla_policy *policy)
{
    return nla_parse(tb, maxtype, nla_data(nla), nla_len(nla), policy);
}

/**
* nla_put_u8 - Add a u8 netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @value: numeric value
*/
static __inline int nla_put_u8(struct sk_buff *msg, int attrtype, __u8 value)
{
    return nla_put(msg, attrtype, sizeof(__u8), &value);
}

/**
* nla_put_u16 - Add a u16 netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @value: numeric value
*/
static __inline int nla_put_u16(struct sk_buff *msg, int attrtype, __u16 value)
{
    return nla_put(msg, attrtype, sizeof(__u16), &value);
}

/**
* nla_put_u32 - Add a u32 netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @value: numeric value
*/
static __inline int nla_put_u32(struct sk_buff *msg, int attrtype, __u32 value)
{
    return nla_put(msg, attrtype, sizeof(__u32), &value);
}

/**
* nla_put_64 - Add a u64 netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @value: numeric value
*/
static __inline int nla_put_u64(struct sk_buff *msg, int attrtype, __u64 value)
{
    return nla_put(msg, attrtype, sizeof(__u64), &value);
}

/**
* nla_put_string - Add a string netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @str: NUL terminated string
*/
static __inline int nla_put_string(struct sk_buff *msg, int attrtype,
    const char *str)
{
    return nla_put(msg, attrtype, (short int)strlen(str) + 1, str);
}

/**
* nla_put_flag - Add a flag netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
*/
static __inline int nla_put_flag(struct sk_buff *msg, int attrtype)
{
    return nla_put(msg, attrtype, 0, NULL);
}

#define NLA_PUT(msg, attrtype, attrlen, data) \
	do { \
		if (unlikely(nla_put(msg, attrtype, attrlen, data) < 0)) \
			goto nla_put_failure; \
    	} while(0)

#define NLA_PUT_TYPE(msg, type, attrtype, value) \
	do { \
		type __tmp = value; \
		NLA_PUT(msg, attrtype, sizeof(type), &__tmp); \
    	} while(0)

#define NLA_PUT_U8(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __u8, attrtype, value)

#define NLA_PUT_U16(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __u16, attrtype, value)

#define NLA_PUT_LE16(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __le16, attrtype, value)

#define NLA_PUT_BE16(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __be16, attrtype, value)

#define NLA_PUT_U32(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __u32, attrtype, value)

#define NLA_PUT_BE32(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __be32, attrtype, value)

#define NLA_PUT_U64(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __u64, attrtype, value)

#define NLA_PUT_BE64(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __be64, attrtype, value)

#define NLA_PUT_STRING(msg, attrtype, value) \
	NLA_PUT(msg, attrtype, strlen(value) + 1, value)

#define NLA_PUT_FLAG(msg, attrtype) \
	NLA_PUT(msg, attrtype, 0, NULL)

/**
 * nla_get_u32 - return payload of u32 attribute
 * @nla: u32 netlink attribute
 */
static __inline __u32 nla_get_u32(const struct nlattr *nla)
{
	return *(__u32 *) nla_data(nla);
}

/**
 * nla_get_be32 - return payload of __be32 attribute
 * @nla: __be32 netlink attribute
 */
static __inline __be32 nla_get_be32(const struct nlattr *nla)
{
	return *(__be32 *) nla_data(nla);
}

/**
 * nla_get_u16 - return payload of u16 attribute
 * @nla: u16 netlink attribute
 */
static __inline __u16 nla_get_u16(const struct nlattr *nla)
{
	return *(__u16 *) nla_data(nla);
}

/**
 * nla_get_be16 - return payload of __be16 attribute
 * @nla: __be16 netlink attribute
 */
static __inline __be16 nla_get_be16(const struct nlattr *nla)
{
	return *(__be16 *) nla_data(nla);
}

/**
 * nla_get_le16 - return payload of __le16 attribute
 * @nla: __le16 netlink attribute
 */
static __inline __le16 nla_get_le16(const struct nlattr *nla)
{
	return *(__le16 *) nla_data(nla);
}

/**
 * nla_get_u8 - return payload of u8 attribute
 * @nla: u8 netlink attribute
 */
static __inline __u8 nla_get_u8(const struct nlattr *nla)
{
	return *(__u8 *) nla_data(nla);
}

/**
 * nla_get_u64 - return payload of u64 attribute
 * @nla: u64 netlink attribute
 */
static __inline __u64 nla_get_u64(const struct nlattr *nla)
{
	__u64 tmp;

	nla_memcpy(&tmp, nla, sizeof(tmp));

	return tmp;
}

/**
 * nla_get_be64 - return payload of __be64 attribute
 * @nla: __be64 netlink attribute
 */
static __inline __be64 nla_get_be64(const struct nlattr *nla)
{
	return *(__be64 *) nla_data(nla);
}

/**
 * nla_get_flag - return payload of flag attribute
 * @nla: flag netlink attribute
 */
static __inline int nla_get_flag(const struct nlattr *nla)
{
	return !!nla;
}

/**
 * nla_nest_start - Start a new level of nested attributes
 * @msg: message buffer to add attributes to
 * @attrtype: attribute type of container
 *
 * Returns the container attribute
 */
static __inline struct nlattr *nla_nest_start(struct sk_buff *msg, int attrtype)
{
	extern unsigned char *skb_tail_pointer(const struct sk_buff *skb);
	struct nlattr *start = (struct nlattr *)skb_tail_pointer(msg);

	if (nla_put(msg, attrtype, 0, NULL) < 0)
		return NULL;

	return start;
}

/**
 * nla_nest_end - Finalize nesting of attributes
 * @msg: message buffer the attributes are stored in
 * @start: container attribute
 *
 * Corrects the container attribute header to include the all
 * appeneded attributes.
 *
 * Returns the total data length of the msg.
 */
static __inline int nla_nest_end(struct sk_buff *msg, struct nlattr *start)
{
	start->nla_len = (u16)(skb_tail_pointer(msg) - (unsigned char *)start);
	return msg->len;
}

/**
 * nla_validate_nested - Validate a stream of nested attributes
 * @start: container attribute
 * @maxtype: maximum attribute type to be expected
 * @policy: validation policy
 *
 * Validates all attributes in the nested attribute stream against the
 * specified policy. Attributes with a type exceeding maxtype will be
 * ignored. See documenation of struct nla_policy for more details.
 *
 * Returns 0 on success or a negative error code.
 */
static __inline int nla_validate_nested(struct nlattr *start, int maxtype,
				      const struct nla_policy *policy)
{
	return nla_validate(nla_data(start), nla_len(start), maxtype, policy);
}

/**
 * nla_for_each_attr - iterate over a stream of attributes
 * @pos: loop counter, set to current attribute
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nla_ok(pos, rem); \
	     pos = nla_next(pos, &(rem)))

/**
 * nla_for_each_nested - iterate over nested attributes
 * @pos: loop counter, set to current attribute
 * @nla: attribute containing the nested attributes
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_nested(pos, nla, rem) \
	nla_for_each_attr(pos, nla_data(nla), nla_len(nla), rem)

static __inline struct nlmsghdr *
	__nlmsg_put(struct sk_buff *skb, u32 portid, u32 seq, u16 type, u16 len, u16 flags)
{
	struct nlmsghdr *nlh;
	u16 size = nlmsg_msg_size(len);

	nlh = (struct nlmsghdr*)skb_put(skb, NLMSG_ALIGN(size));
	nlh->nlmsg_type = type;
	nlh->nlmsg_len = size;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_pid = portid;
	nlh->nlmsg_seq = seq;

	if (NLMSG_ALIGN(size) - size != 0)
	{
		//memset( (int)nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size);
		memset((unsigned char*)nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size); // 기존 (int)로 형변환 이유?... 확인필요.
	}

	return nlh;
}

static __inline struct nlmsghdr *nlmsg_put(struct sk_buff *skb, u32 portid, u32 seq,
	u16 type, u16 payload, u16 flags)
{
	return __nlmsg_put(skb, portid, seq, type, payload, flags);
}

static __inline int nlmsg_end(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    nlh->nlmsg_len = (u16)(skb_tail_pointer(skb) - (unsigned char *)nlh);
    return skb->len;
}

static __inline int genlmsg_end(struct sk_buff *skb, void *hdr)
{
    return nlmsg_end(skb, (void*)((ULONG_PTR)hdr - GENL_HDRLEN - NLMSG_HDRLEN) );
}

/**
* gennlmsg_data - head of message payload
* @gnlh: genetlink messsage header
*/
static __inline void *genlmsg_data(const struct genlmsghdr *gnlh)
{
    return ((unsigned char *)gnlh + GENL_HDRLEN);
}

extern int genlmsg_unicast(struct sk_buff *skb, struct genl_info *info);
#endif __DRBD_WINGENL_H__
