#ifndef _LINUX_MODULEPARAM_H
#define _LINUX_MODULEPARAM_H

#define module_param_string(...)

#define MODULE_PARM_DESC(x, ...)

struct kernel_param;

/*
 * Flags available for kernel_param_ops
 *
 * NOARG - the parameter allows for no argument (foo instead of foo=1)
 */
enum {
	KERNEL_PARAM_OPS_FL_NOARG = (1 << 0)
};

struct kernel_param_ops {
	/* How the ops should behave */
	unsigned int flags;
	/* Returns 0, or -errno.  arg is in kp->arg. */
	int (*set)(const char *val, const struct kernel_param *kp);
	/* Returns length written or -errno.  Buffer is 4k (ie. be short!) */
	int (*get)(char *buffer, const struct kernel_param *kp);
	/* Optional function to free kp->arg when module unloaded. */
	void (*free)(void *arg);
};

struct kernel_param {
	const char *name;
	struct module *mod;
	const struct kernel_param_ops *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array *arr;
	};
};

/* Special one for strings we want to copy into */
struct kparam_string {
	unsigned int maxlen;
	char *string;
};

/* Special one for arrays */
struct kparam_array
{
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops *ops;
	void *elem;
};

extern int param_get_uint(char *buffer, const struct kernel_param *kp);

#if 0
/* The macros to do compile-time type checking stolen from Jakub
   Jelinek, who IIRC came up with this idea for the 2.4 module init code. */
#define __param_check(name, p, type) \
	static inline type __always_unused *__check_##name(void) { return(p); }

#define param_check_uint(name, p) __param_check(name, p, unsigned int)
#endif

extern const struct kernel_param_ops param_ops_bool;
extern int param_set_bool(const char *val, const struct kernel_param *kp);
extern int param_get_bool(char *buffer, const struct kernel_param *kp);

extern const struct kernel_param_ops param_ops_uint;
extern int param_set_uint(const char *val, const struct kernel_param *kp);
extern int param_get_uint(char *buffer, const struct kernel_param *kp);

extern const struct kernel_param_ops param_ops_int;
extern int param_set_int(const char *val, const struct kernel_param *kp);
extern int param_get_int(char *buffer, const struct kernel_param *kp);

/**
 * module_param_named - typesafe helper for a renamed module/cmdline parameter
 * @name: a valid C identifier which is the parameter name.
 * @value: the actual lvalue to alter.
 * @type: the type of the parameter
 * @perm: visibility in sysfs.
 *
 * Usually it's a good idea to have variable names and user-exposed names the
 * same, but that's harder if the variable must be non-static or is inside a
 * structure.  This allows exposure under a different name.
 */

/* TODO: note that this is just to silence a warning in drbd_main.c
 * since we do not have sections on Windows (at least not supported
 * by the MinGW gcc we cannot use the Linux macros ...
 */

// extern const struct kernel_param_ops param_ops_uint;

#define module_param_named(name, value, type, perm) \
	const struct kernel_param_ops *dummy_ ## value;

#define __MODULE_INFO(tag, name, info)  /* nothing */

#if 0
        static const char (name)[]                                        \
                = __stringify(tag) "=" info
#endif

#define module_param_cb(name, ops, arg, perm) /* nothing */	

#endif
