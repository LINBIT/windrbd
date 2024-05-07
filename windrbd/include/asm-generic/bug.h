#ifndef __ASM_GENERIC_BUG_H
#define __ASM_GENERIC_BUG_H

#include <linux/panic.h>
#include <linux/printk.h>

/* TODO: don't panic? */

#define BUG() do { \
	printk("BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
	panic("BUG!"); \
} while (0)
#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while (0)

#define WARN(condition, format...) ({ \
	if (condition) printk("Warning: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
})

#define WARN_ON(condition) do { if (unlikely(condition)) WARN(condition); } while (0)

#define WARN_ONCE(condition, args...) WARN(condition, args)

#endif
