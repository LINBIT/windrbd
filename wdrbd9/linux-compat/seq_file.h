#ifndef __SEQ_FILE_H__
#define __SEQ_FILE_H__
#include "drbd_windows.h"
struct seq_file
{
    char buf[MAX_PROC_BUF];
    void * private;
};


extern int seq_file_idx;

extern int seq_printf(struct seq_file *m, const char *f, ...);

extern int seq_putc(struct seq_file *m, char c);
extern int seq_puts(struct seq_file *m, const char *s);

#endif