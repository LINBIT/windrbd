#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <linux/fs.h>

extern void fput(struct file *);

#endif
