#ifndef __LINUX_PROC_FS_H
#define __LINUX_PROC_FS_H

struct proc_dir_entry {
	int dummy;
};

static inline void remove_proc_entry(const char *, struct proc_dir_entry *)
{
	/* TODO: stub */
}

#endif
