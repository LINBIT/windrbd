#ifndef __LINUX_SKBUFF_H
#define __LINUX_SKBUFF_H

struct sk_buff
{
	size_t len;
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

	unsigned char data[1];
};

extern unsigned char *skb_put(struct sk_buff *skb, unsigned int len);

#endif
