#ifndef __LINUX_KMOD_H
#define __LINUX_KMOD_H

/* TODO: not supported and also not needed. There is only one
 * module at the moment.
 */

static inline int request_module(const char *name, ...)
{
	return 0;
}

#endif
