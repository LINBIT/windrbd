#ifndef __LINUX_VMALLOC_H
#define __LINUX_VMALLOC_H

	/* This should map to kmalloc() */
extern void *__vmalloc(unsigned long size, gfp_t gfp_mask);

#endif
