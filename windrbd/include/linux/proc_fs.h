#ifndef __LINUX_PROC_FS_H
#define __LINUX_PROC_FS_H

struct proc_dir_entry {
	int dummy;
};

static inline struct proc_dir_entry *proc_create_single_data(const char *name, umode_t mode,
		struct proc_dir_entry *parent,
		int (*show)(struct seq_file *, void *), void *data)
{
	/* TODO: stub */
	return NULL;
}

#define proc_create_single(name, mode, parent, show) \
	proc_create_single_data(name, mode, parent, show, NULL)
 
static inline void remove_proc_entry(const char *, struct proc_dir_entry *)
{
	/* TODO: stub */
}

#endif
