#ifndef __LINUX_NET_NAMESPACE
#define __LINUX_NET_NAMESPACE

#include <linux/list.h>

/* We do not support net namespaces. */

struct net {
	int dummy;
};

extern struct net init_net;

#define __net_exit	/* nothing */

struct pernet_operations {
	struct list_head list;
	/*
	 * Below methods are called without any exclusive locks.
	 * More than one net may be constructed and destructed
	 * in parallel on several cpus. Every pernet_operations
	 * have to keep in mind all other pernet_operations and
	 * to introduce a locking, if they share common resources.
	 *
	 * The only time they are called with exclusive lock is
	 * from register_pernet_subsys(), unregister_pernet_subsys()
	 * register_pernet_device() and unregister_pernet_device().
	 *
	 * Exit methods using blocking RCU primitives, such as
	 * synchronize_rcu(), should be implemented via exit_batch.
	 * Then, destruction of a group of net requires single
	 * synchronize_rcu() related to these pernet_operations,
	 * instead of separate synchronize_rcu() for every net.
	 * Please, avoid synchronize_rcu() at all, where it's possible.
	 *
	 * Note that a combination of pre_exit() and exit() can
	 * be used, since a synchronize_rcu() is guaranteed between
	 * the calls.
	 */
	int (*init)(struct net *net);
	void (*pre_exit)(struct net *net);
	void (*exit)(struct net *net);
	void (*exit_batch)(struct list_head *net_exit_list);
	/* Following method is called with RTNL held. */
	void (*exit_batch_rtnl)(struct list_head *net_exit_list,
				struct list_head *dev_kill_list);
	unsigned int * const id;
	const size_t size;
};

static inline int register_pernet_device(struct pernet_operations *unused)
{
	return 0;
}

static inline void unregister_pernet_device(struct pernet_operations *unused)
{
}

#endif
