#ifndef __LINUX_SKBUFF_H
#define __LINUX_SKBUFF_H

#include <net/netmem.h>

struct sk_buff
{
	unsigned int len;
	unsigned int data_len;
		/* Maybe TODO: In current Linux versions these are
		 * pointers into the data buffer.
		 */

	size_t tail;
	size_t end;

	/*
	 * This is the control buffer. It is free to use for every
	 * layer. Please put your private variables there. If you
	 * want to keep them across layers you have to do a skb_clone()
	 * first. This is owned by whoever has the skb queued ATM.
	 */

	char cb[48];
	struct sock *sk;

	unsigned char data[1];
};

extern unsigned char *skb_put(struct sk_buff *skb, unsigned int len);

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
}

/*
static inline unsigned char *skb_end_pointer(const struct sk_buff *skb)
{
	return skb->head + skb->end;
}
*/

struct skb_seq_state {
	__u32		lower_offset;
	__u32		upper_offset;
	__u32		frag_idx;
	__u32		stepped_offset;
	struct sk_buff	*root_skb;
	struct sk_buff	*cur_skb;
	__u8		*frag_data;
	__u32		frag_off;
};

typedef struct skb_frag {
	netmem_ref netmem;
	unsigned int len;
	unsigned int offset;
} skb_frag_t;

#define skb_shinfo(SKB)	((struct skb_shared_info *)(skb_end_pointer(SKB)))

#endif
