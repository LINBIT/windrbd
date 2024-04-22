#ifndef __ASM_GENERIC_BUG_H
#define __ASM_GENERIC_BUG_H

/* TODO: those should be noreturn somehow ... getting complaints from
 * the compiler about that ... */

#define BUG() do { \
	printk("BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
} while (0)
#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while (0)

#define WARN() do { \
	printk("Warning: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
} while (0)
#define WARN_ON(condition) do { if (unlikely(condition)) WARN(); } while (0)

#endif
