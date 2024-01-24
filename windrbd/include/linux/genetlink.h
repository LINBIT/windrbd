#ifndef _LINUX_GENETLINK_H
#define _LINUX_GENETLINK_H

struct genl_multicast_group {
	struct genl_family	*family;	/* private */
        struct list_head	list;		/* private */
        char			name[GENL_NAMSIZ];
	u32			id;
};

#endif
