#ifdef USER_MODE

#include <string.h>

#define container_of(ptr, type, member) \
        ((type *)( \
        (char*)(ptr) - \
        (unsigned long)(&((type *)0)->member)))

#include <linux/list.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <linux/drbd_limits.h>

#define printk printf
#define kmalloc(size, unused, unused2) malloc(size)

#else		/* windows kernel */

#include <drbd_windows.h>
#include <linux/list.h>
#include <linux/drbd_limits.h>

#endif

struct net_params {
	bool use_rle;
	char *verify_alg;
	int timeout;
	int ping_timeout;
	int ping_int;
	int connect_int;
};

struct disk_params {
	int c_max_rate;
	int c_fill_target;
};

	/* for now we allow only for one volume because that is
	 * what WinDRBD boot feature needs.
	 */

struct volume {
	int minor;
	char *disk;
	char *meta_disk;
#if 0
	wchar_t *mount_point; /* might be NULL */
#endif
};
	
struct node {
	struct list_head list;

	char *hostname;
	int node_id;
	char *address;
	struct volume volume;
};

struct drbd_params {
	struct net_params net;
	struct disk_params disk;
	struct list_head node_list;

	char *resource;
	int protocol;	/* 1=A, 2=B or 3=C */
	int volume_id;	/* must be the same on all nodes. More
			 * than one volume currently not supported
			 * (don't need it to boot windows).
			 */
	char *syslog_ip;
	int this_node_id; /* My node id (the Windows client) */
	int num_nodes;	/* Derived from nodeN= key/value pairs */
};

	/* Returns 0 on success, negative values on failure. */

int parse_drbd_url(const char *drbd_config, struct drbd_params *params);
