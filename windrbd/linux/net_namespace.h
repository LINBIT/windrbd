/* We do not support net namespaces. */

struct net {
	int dummy;
};

extern struct net init_net;
