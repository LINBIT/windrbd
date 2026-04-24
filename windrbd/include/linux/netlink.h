#ifndef _NETLINK_H
#define _NETLINK_H


#ifndef __DRBD_WINGENL_H__
#define __DRBD_WINGENL_H__

#include <linux/types.h>
#include <wsk.h>
#include <linux/list.h>
#include <uapi/linux/netlink.h>
#include <linux/skbuff.h>

static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buff *skb)
{
	return (struct nlmsghdr *)skb->data;
}

static inline size_t skb_is_nonlinear(const struct sk_buff *skb)
{
	return skb->len;
}

static inline unsigned char *skb_tail_pointer(const struct sk_buff *skb)
{
	return (unsigned char*)((size_t)skb->data + (size_t) skb->tail);
}

/**
 *	skb_tailroom - bytes at buffer end
 *	@skb: buffer to check
 *
 *	Return the number of bytes of free space at the tail of an sk_buff
 */
static inline size_t skb_tailroom(const struct sk_buff *skb)
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

/**
 * struct genl_split_ops - generic netlink operations (do/dump split version)
 * @cmd: command identifier
 * @internal_flags: flags used by the family
 * @flags: GENL_* flags (%GENL_ADMIN_PERM or %GENL_UNS_ADMIN_PERM)
 * @validate: validation flags from enum genl_validate_flags
 * @policy: netlink policy (takes precedence over family policy)
 * @maxattr: maximum number of attributes supported
 *
 * Do callbacks:
 * @pre_doit: called before an operation's @doit callback, it may
 *	do additional, common, filtering and return an error
 * @doit: standard command callback
 * @post_doit: called after an operation's @doit callback, it may
 *	undo operations done by pre_doit, for example release locks
 *
 * Dump callbacks:
 * @start: start callback for dumps
 * @dumpit: callback for dumpers
 * @done: completion callback for dumps
 *
 * Do callbacks can be used if %GENL_CMD_CAP_DO is set in @flags.
 * Dump callbacks can be used if %GENL_CMD_CAP_DUMP is set in @flags.
 * Exactly one of those flags must be set.
 */
struct genl_split_ops {
	union {
		struct {
			int (*pre_doit)(const struct genl_split_ops *ops,
					struct sk_buff *skb,
					struct genl_info *info);
			int (*doit)(struct sk_buff *skb,
				    struct genl_info *info);
			void (*post_doit)(const struct genl_split_ops *ops,
					  struct sk_buff *skb,
					  struct genl_info *info);
		};
		struct {
			int (*start)(struct netlink_callback *cb);
			int (*dumpit)(struct sk_buff *skb,
				      struct netlink_callback *cb);
			int (*done)(struct netlink_callback *cb);
		};
	};
	const struct nla_policy *policy;
	unsigned int		maxattr;
	u8			cmd;
	u8			internal_flags;
	u8			flags;
	u8			validate;
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
    const struct nla_policy *policy;
	u8			parallel_ops:1;
	/* New with DRBD 9.1: TODO: what does this? */
	bool	netnsok;

        u8                      n_ops;
        const struct genl_ops * ops;
        u8                      n_mcgrps;
        const struct genl_multicast_group *mcgrps;
        struct module           *module;

	int			(*pre_doit)(const struct genl_split_ops *ops,
					    struct sk_buff *skb,
					    struct genl_info *info);
	void			(*post_doit)(const struct genl_split_ops *ops,
					     struct sk_buff *skb,
					     struct genl_info *info);
};

extern const struct genl_family *the_windrbd_netlink_family;

static inline int genl_register_family(struct genl_family *family)
{
        the_windrbd_netlink_family = family;

	return 0;
}

#define NETLINK_CTX_SIZE	48

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
    	union {
		u8		ctx[NETLINK_CTX_SIZE];
		void *		user_ptr[2];
	};

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
    NLA_S8,
    NLA_S16,
    NLA_S32,
    NLA_S64,
    NLA_BITFIELD32,
    NLA_REJECT,
    NLA_BE16,
    NLA_BE32,
    NLA_SINT,
    NLA_UINT,
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
static inline u16 nlmsg_msg_size(u16 payload)
{
    return NLMSG_HDRLEN + payload;
}

/**
* nlmsg_total_size - length of netlink message including padding
* @payload: length of message payload
*/
static inline u16 nlmsg_total_size(u16 payload)
{
    return NLMSG_ALIGN(nlmsg_msg_size(payload));
}

/**
* nlmsg_padlen - length of padding at the message's tail
* @payload: length of message payload
*/
static inline u16 nlmsg_padlen(u16 payload)
{
    return nlmsg_total_size(payload) - nlmsg_msg_size(payload);
}

/**
* nlmsg_data - head of message payload
* @nlh: netlink messsage header
*/
static inline void *nlmsg_data(const struct nlmsghdr *nlh)
{
    return (unsigned char *)nlh + NLMSG_HDRLEN;
}

/**
* nlmsg_len - length of message payload
* @nlh: netlink message header
*/
static inline int nlmsg_len(const struct nlmsghdr *nlh)
{
    return nlh->nlmsg_len - NLMSG_HDRLEN;
}

/**
* nlmsg_attrdata - head of attributes data
* @nlh: netlink message header
* @hdrlen: length of family specific header
*/
static inline struct nlattr *nlmsg_attrdata(const struct nlmsghdr *nlh,
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
static inline int nlmsg_attrlen(const struct nlmsghdr *nlh, int hdrlen)
{
    return nlmsg_len(nlh) - NLMSG_ALIGN(hdrlen);
}

/**
* nlmsg_ok - check if the netlink message fits into the remaining bytes
* @nlh: netlink message header
* @remaining: number of bytes remaining in message stream
*/
static inline int nlmsg_ok(const struct nlmsghdr *nlh, int remaining)
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
static inline void nlmsg_trim(struct sk_buff *skb, const void *mark)
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
static inline int nla_attr_size(int payload)
{
    return NLA_HDRLEN + payload;
}

/**
* nla_total_size - total length of attribute including padding
* @payload: length of payload
*/
static inline int nla_total_size(int payload)
{
    return NLA_ALIGN(nla_attr_size(payload));
}

/**
* nla_padlen - length of padding at the tail of attribute
* @payload: length of payload
*/
static inline int nla_padlen(int payload)
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
static inline int nla_type(const struct nlattr *nla)
{
    return nla->nla_type & NLA_TYPE_MASK;
}

/**
* nla_data - head of payload
* @nla: netlink attribute
*/
static inline void *nla_data(const struct nlattr *nla)
{
    return (char *)nla + NLA_HDRLEN;
}


/**
* nla_len - length of payload
* @nla: netlink attribute
*/

static inline int nla_len(const struct nlattr *nla)
{
    return nla->nla_len - NLA_HDRLEN;
}

//#endif
/**
* nla_ok - check if the netlink attribute fits into the remaining bytes
* @nla: netlink attribute
* @remaining: number of bytes remaining in attribute stream
*/
static inline int nla_ok(const struct nlattr *nla, int remaining)
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
static inline struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
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
static inline struct nlattr *nla_find_nested(struct nlattr *nla, int attrtype)
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
static inline int nla_parse_nested(struct nlattr *tb[], int maxtype,
    const struct nlattr *nla,
    const struct nla_policy *policy)
{
    return nla_parse(tb, maxtype, nla_data(nla), nla_len(nla), policy);
}

/**
 * nla_parse_nested_deprecated - parse nested attributes
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @nla: attribute containing the nested attributes
 * @policy: validation policy
 * @extack: extended ACK report struct
 *
 * See nla_parse_deprecated()
 */

struct netlink_ext_ack; /* Not used. */

static inline int nla_parse_nested_deprecated(struct nlattr *tb[], int maxtype,
					      const struct nlattr *nla,
					      const struct nla_policy *policy,
					      struct netlink_ext_ack *extack)
{
	return nla_parse_nested(tb, maxtype, nla, policy);
}

/**
* nla_put_u8 - Add a u8 netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @value: numeric value
*/
static inline int nla_put_u8(struct sk_buff *msg, int attrtype, __u8 value)
{
    return nla_put(msg, attrtype, sizeof(__u8), &value);
}

/**
* nla_put_u16 - Add a u16 netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @value: numeric value
*/
static inline int nla_put_u16(struct sk_buff *msg, int attrtype, __u16 value)
{
    return nla_put(msg, attrtype, sizeof(__u16), &value);
}

/**
* nla_put_u32 - Add a u32 netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @value: numeric value
*/
static inline int nla_put_u32(struct sk_buff *msg, int attrtype, __u32 value)
{
    return nla_put(msg, attrtype, sizeof(__u32), &value);
}

/**
* nla_put_64 - Add a u64 netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @value: numeric value
*/
static inline int nla_put_u64(struct sk_buff *msg, int attrtype, __u64 value)
{
    return nla_put(msg, attrtype, sizeof(__u64), &value);
}


/**
 * nla_put_s8 - Add a s8 netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_s8(struct sk_buff *skb, int attrtype, s8 value)
{
	s8 tmp = value;

	return nla_put(skb, attrtype, sizeof(s8), &tmp);
}

/**
 * nla_put_s16 - Add a s16 netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_s16(struct sk_buff *skb, int attrtype, s16 value)
{
	s16 tmp = value;

	return nla_put(skb, attrtype, sizeof(s16), &tmp);
}

/**
 * nla_put_s32 - Add a s32 netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_s32(struct sk_buff *skb, int attrtype, s32 value)
{
	s32 tmp = value;

	return nla_put(skb, attrtype, sizeof(s32), &tmp);
}

static inline bool nla_need_padding_for_64bit(struct sk_buff *skb)
{
	return false;
}

static inline int nla_total_size_64bit(int payload)
{
	return NLA_ALIGN(nla_attr_size(payload));
}

static inline struct nlattr *__nla_reserve_64bit(struct sk_buff *skb, int attrtype,
				   int attrlen, int padattr)
{
	return __nla_reserve(skb, attrtype, attrlen);
}

static inline void __nla_put_64bit(struct sk_buff *skb, int attrtype, int attrlen,
		     const void *data, int padattr)
{
	struct nlattr *nla;

	nla = __nla_reserve_64bit(skb, attrtype, attrlen, padattr);
	memcpy(nla_data(nla), data, attrlen);
}

static inline int nla_put_64bit(struct sk_buff *skb, int attrtype, int attrlen,
		  const void *data, int padattr)
{
	size_t len;

	if (nla_need_padding_for_64bit(skb))
		len = nla_total_size_64bit(attrlen);
	else
		len = nla_total_size(attrlen);
	if (unlikely(skb_tailroom(skb) < len))
		return -EMSGSIZE;

	__nla_put_64bit(skb, attrtype, attrlen, data, padattr);
	return 0;
}

/**
 * nla_put_s64 - Add a s64 netlink attribute to a socket buffer and align it
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 * @padattr: attribute type for the padding
 */
static inline int nla_put_s64(struct sk_buff *skb, int attrtype, s64 value,
			      int padattr)
{
	s64 tmp = value;

	return nla_put_64bit(skb, attrtype, sizeof(s64), &tmp, padattr);
}

/**
* nla_put_string - Add a string netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @str: NUL terminated string
*/
static inline int nla_put_string(struct sk_buff *msg, int attrtype,
    const char *str)
{
    return nla_put(msg, attrtype, (short int)strlen(str) + 1, str);
}

/**
* nla_put_flag - Add a flag netlink attribute to a message buffer
* @msg: message buffer to add attribute to
* @attrtype: attribute type
*/
static inline int nla_put_flag(struct sk_buff *msg, int attrtype)
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
 * nla_get_s32 - return payload of s32 attribute
 * @nla: s32 netlink attribute
 */
static inline s32 nla_get_s32(const struct nlattr *nla)
{
	return *(s32 *) nla_data(nla);
}

/**
 * nla_get_u32 - return payload of u32 attribute
 * @nla: u32 netlink attribute
 */
static inline __u32 nla_get_u32(const struct nlattr *nla)
{
	return *(__u32 *) nla_data(nla);
}

/**
 * nla_get_be32 - return payload of __be32 attribute
 * @nla: __be32 netlink attribute
 */
static inline __be32 nla_get_be32(const struct nlattr *nla)
{
	return *(__be32 *) nla_data(nla);
}

/**
 * nla_get_u16 - return payload of u16 attribute
 * @nla: u16 netlink attribute
 */
static inline __u16 nla_get_u16(const struct nlattr *nla)
{
	return *(__u16 *) nla_data(nla);
}

/**
 * nla_get_be16 - return payload of __be16 attribute
 * @nla: __be16 netlink attribute
 */
static inline __be16 nla_get_be16(const struct nlattr *nla)
{
	return *(__be16 *) nla_data(nla);
}

/**
 * nla_get_le16 - return payload of __le16 attribute
 * @nla: __le16 netlink attribute
 */
static inline __le16 nla_get_le16(const struct nlattr *nla)
{
	return *(__le16 *) nla_data(nla);
}

/**
 * nla_get_u8 - return payload of u8 attribute
 * @nla: u8 netlink attribute
 */
static inline __u8 nla_get_u8(const struct nlattr *nla)
{
	return *(__u8 *) nla_data(nla);
}

/**
 * nla_get_u64 - return payload of u64 attribute
 * @nla: u64 netlink attribute
 */
static inline __u64 nla_get_u64(const struct nlattr *nla)
{
	__u64 tmp;

	nla_memcpy(&tmp, nla, sizeof(tmp));

	return tmp;
}

/**
 * nla_get_be64 - return payload of __be64 attribute
 * @nla: __be64 netlink attribute
 */
static inline __be64 nla_get_be64(const struct nlattr *nla)
{
	return *(__be64 *) nla_data(nla);
}

/**
 * nla_get_flag - return payload of flag attribute
 * @nla: flag netlink attribute
 */
static inline int nla_get_flag(const struct nlattr *nla)
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
static inline struct nlattr *nla_nest_start(struct sk_buff *msg, int attrtype)
{
	extern unsigned char *skb_tail_pointer(const struct sk_buff *skb);
	struct nlattr *start = (struct nlattr *)skb_tail_pointer(msg);

	if (nla_put(msg, attrtype, 0, NULL) < 0)
		return NULL;

	return start;
}

/**
 * nla_nest_start_noflag - Start a new level of nested attributes
 * @skb: socket buffer to add attributes to
 * @attrtype: attribute type of container
 *
 * This function exists for backward compatibility to use in APIs which never
 * marked their nest attributes with NLA_F_NESTED flag. New APIs should use
 * nla_nest_start() which sets the flag.
 *
 * Returns the container attribute or NULL on error
 */

static inline struct nlattr *nla_nest_start_noflag(struct sk_buff *skb,
						   int attrtype)
{
	struct nlattr *start = (struct nlattr *)skb_tail_pointer(skb);

	if (nla_put(skb, attrtype, 0, NULL) < 0)
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
static inline size_t nla_nest_end(struct sk_buff *msg, struct nlattr *start)
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
static inline int nla_validate_nested(struct nlattr *start, int maxtype,
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

static inline struct nlmsghdr *
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
		memset((unsigned char*)nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size);

	return nlh;
}

static inline struct nlmsghdr *nlmsg_put(struct sk_buff *skb, u32 portid, u32 seq,
	u16 type, u16 payload, u16 flags)
{
	return __nlmsg_put(skb, portid, seq, type, payload, flags);
}

static inline ssize_t nlmsg_end(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    nlh->nlmsg_len = (u16)(skb_tail_pointer(skb) - (unsigned char *)nlh);
    return skb->len;
}

static inline ssize_t genlmsg_end(struct sk_buff *skb, void *hdr)
{
    return nlmsg_end(skb, (void*)((ULONG_PTR)hdr - GENL_HDRLEN - NLMSG_HDRLEN) );
}

extern int genlmsg_unicast(struct sk_buff *skb, struct genl_info *info);

static inline int genlmsg_reply(struct sk_buff *skb, struct genl_info *info)
{
	return genlmsg_unicast(skb, info);
}

/**
* gennlmsg_data - head of message payload
* @gnlh: genetlink messsage header
*/
static inline void *genlmsg_data(const struct genlmsghdr *gnlh)
{
    return ((unsigned char *)gnlh + GENL_HDRLEN);
}

extern int genlmsg_multicast(struct sk_buff *skb, u32 portid,
			    unsigned int group, gfp_t flags);

/**
 * genlmsg_multicast_allns - multicast a netlink message to all net namespaces
 * @family: the generic netlink family
 * @skb: netlink message as socket buffer
 * @portid: own netlink portid to avoid sending to yourself
 * @group: offset of multicast group in groups array
 *
 * This function must hold the RTNL or rcu_read_lock().
 */
extern int genlmsg_multicast_allns(const struct genl_family *family,
                            struct sk_buff *skb, u32 portid,
                            unsigned int group);


/* Those two now patched into drbd_nl.c */
extern struct genl_ops * get_drbd_genl_ops(u8 cmd);
extern int drbd_tla_parse(struct nlmsghdr *nlh, struct nlattr **attr);
// extern void drbd_adm_send_reply(struct sk_buff *skb, struct genl_info *info);
extern const char *windrbd_genl_cmd_to_str(u8 cmd);

ssize_t nla_strscpy(char *dst, const struct nlattr *nla, size_t dstsize);

#endif
struct netlink_skb_parms {
	__u32			portid;
};

#define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))

#endif

