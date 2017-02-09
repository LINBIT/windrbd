#ifndef DRBD_POLYMORPH_PRINTK_H
#define DRBD_POLYMORPH_PRINTK_H

#define __drbd_printk_device(level, device, fmt, ...)		\
    do {								\
        const struct drbd_device *__d = (device);		\
        const struct drbd_resource *__r = __d->resource;	\
        printk(level "drbd %s/%u minor %u, ds(%s), dvflag(0x%x): " fmt,			\
            __r->name, __d->vnr, __d->minor, drbd_disk_str(__d->disk_state[NOW]), __d->flags, __VA_ARGS__);	\
    } while (0)

#define __drbd_printk_peer_device(level, peer_device, fmt, ...)	\
    do {								\
        const struct drbd_device *__d;				\
        const struct drbd_connection *__c;			\
        const struct drbd_resource *__r;			\
        int __cn;					\
        /*rcu_read_lock();		_WIN32 // DW-	*/		\
        __d = (peer_device)->device;				\
        __c = (peer_device)->connection;			\
        __r = __d->resource;					\
        __cn = __c->peer_node_id;	\
        printk(level "drbd %s/%u minor %u pnode-id:%d, pdsk(%s), prpl(%s), pdvflag(0x%x): " fmt,		\
            __r->name, __d->vnr, __d->minor, __cn, drbd_disk_str((peer_device)->disk_state[NOW]), drbd_repl_str((peer_device)->repl_state[NOW]), (peer_device)->flags, __VA_ARGS__);\
        /*rcu_read_unlock();	_WIN32 // DW-	*/		\
    } while (0)

#define __drbd_printk_resource(level, resource, fmt, ...) \
	printk(level "drbd %s, r(%s), f(0x%x), scf(0x%x): " fmt, (resource)->name, drbd_role_str((resource)->role[NOW]), (resource)->flags,(resource)->state_change_flags, __VA_ARGS__)

#define __drbd_printk_connection(level, connection, fmt, ...) \
    do {	                    \
        /*rcu_read_lock();	_WIN32 // DW- */ \
        printk(level "drbd %s pnode-id:%d, cs(%s), prole(%s), cflag(0x%x), scf(0x%x): " fmt, (connection)->resource->name,  \
        (connection)->peer_node_id, drbd_conn_str((connection)->cstate[NOW]), drbd_role_str((connection)->peer_role[NOW]), (connection)->flags,(connection)->resource->state_change_flags, __VA_ARGS__); \
        /*rcu_read_unlock(); _WIN32 // DW- */ \
    } while(0)

#define __drbd_printk_twopc_parent(level, twopc_parent, fmt, ...) \
    do {	                    \
        printk(level fmt, __VA_ARGS__); \
    } while(0)


void drbd_printk_with_wrong_object_type(void);

#define __drbd_printk_if_same_type(obj, type, func, level, fmt, ...) 

#define drbd_printk(level, obj, fmt, ...)   \
    do {    \
        __drbd_printk_##obj(level, obj, fmt, __VA_ARGS__);  \
    } while(0)

#if defined(disk_to_dev)
#define drbd_dbg(device, fmt, args...) \
	dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#elif defined(DBG)
#define drbd_dbg(device, fmt, ...) \
	drbd_printk(KERN_DEBUG, device, fmt, __VA_ARGS__)
#else
#define drbd_dbg(device, fmt, ...) \
	do { if (0) drbd_printk(KERN_DEBUG, device, fmt, __VA_ARGS__); } while (0)
#endif

#if defined(dynamic_dev_dbg) && defined(disk_to_dev)
#define dynamic_drbd_dbg(device, fmt, args...) \
	dynamic_dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#elif defined(_WIN32) && defined(DBG)
#define dynamic_drbd_dbg(device, fmt, ...) \
	drbd_dbg(device, fmt, __VA_ARGS__)
#else
#define dynamic_drbd_dbg(device, fmt, ...)
#endif

#define drbd_emerg(device, fmt, ...) \
	drbd_printk(KERN_EMERG, device, fmt, __VA_ARGS__)
#define drbd_alert(device, fmt, ...) \
	drbd_printk(KERN_ALERT, device, fmt, __VA_ARGS__)
#define drbd_err(device, fmt, ...) \
	drbd_printk(KERN_ERR, device, fmt, __VA_ARGS__)
#define drbd_warn(device, fmt, ...) \
	drbd_printk(KERN_WARNING, device, fmt, __VA_ARGS__)
#define drbd_info(device, fmt, ...) \
	drbd_printk(KERN_INFO, device, fmt, __VA_ARGS__)

#if defined(DBG)
#define drbd_debug(obj, fmt, ...) \
	drbd_printk(KERN_DEBUG, obj, fmt, __VA_ARGS__)
#else
#define drbd_debug(obj, fmt, ...) drbd_printk(KERN_DEBUG, obj, fmt, __VA_ARGS__)
#endif

#define DEFAULT_RATELIMIT_INTERVAL      (5 * HZ)
#define DEFAULT_RATELIMIT_BURST         10

struct ratelimit_state {
	spinlock_t		lock;           /* protect the state */
	int             interval;
	int             burst;
	int             printed;
	int             missed;
	ULONG_PTR	    begin;
};

extern struct ratelimit_state drbd_ratelimit_state;

extern int _DRBD_ratelimit(struct ratelimit_state *rs, const char * func, const char * __FILE, const int __LINE);
#define drbd_ratelimit() _DRBD_ratelimit(&drbd_ratelimit_state, __FUNCTION__, __FILE__, __LINE__)

#define D_ASSERT(x, exp) \
	do { \
		if (!(exp))	{ \
			DbgPrint("\n\nASSERTION %s FAILED in %s #########\n\n",	\
				 #exp, __func__); \
		} \
	} while (0)


/**
 * expect  -  Make an assertion
 *
 * Unlike the assert macro, this macro returns a boolean result.
 */
static inline bool static_inline_expect_fn_peer_device(struct drbd_peer_device *peer_device, int expr, const char *expr_string, const char *fn)
{
	if (!expr && drbd_ratelimit())
		drbd_err(peer_device, "ASSERTION %s FAILED in %s\n", expr_string, fn);
	return expr;
}
static inline bool static_inline_expect_fn_device(struct drbd_device *device, int expr, const char *expr_string, const char *fn)
{
	if (!expr && drbd_ratelimit())
		drbd_err(device, "ASSERTION %s FAILED in %s\n", expr_string, fn);
	return expr;
}
static inline bool static_inline_expect_fn_resource(struct drbd_resource *resource, int expr, const char *expr_string, const char *fn)
{
	if (!expr && drbd_ratelimit())
		drbd_err(resource, "ASSERTION %s FAILED in %s\n", expr_string, fn);
	return expr;
}
static inline bool static_inline_expect_fn_connection(struct drbd_connection *connection, int expr, const char *expr_string, const char *fn)
{
	if (!expr && drbd_ratelimit())
		drbd_err(connection, "ASSERTION %s FAILED in %s\n", expr_string, fn);
	return expr;
}
#define expect(x, expr) static_inline_expect_fn_##x(x, !!(expr), #expr, __FUNCTION__)


#endif
