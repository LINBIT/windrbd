#ifndef __LINUX_PROC_FS_H
#define __LINUX_PROC_FS_H

#include <linux/types.h>
#include <linux/seq_file.h>

struct proc_dir_entry {
	int dummy;
};

extern struct proc_dir_entry the_proc;

static inline struct proc_dir_entry *proc_create_single_data(const char *name, umode_t mode,
		struct proc_dir_entry *parent,
		int (*show)(struct seq_file *, void *), void *data)
{
	/* TODO: stub */
	/* Must return something != NULL else drbd_init will fail ... */
	return &the_proc;
}

#define proc_create_single(name, mode, parent, show) \
	proc_create_single_data(name, mode, parent, show, NULL)
 
static inline void remove_proc_entry(const char *name, struct proc_dir_entry *parent)
{
	/* TODO: stub */
}

#endif
