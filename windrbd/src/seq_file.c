#include "linux/seq_file.h"

int seq_putc(struct seq_file *m, char c)
{
    return 0;
}

int seq_puts(struct seq_file *m, const char *s)
{
    return 0;
}


int seq_printf(struct seq_file *m, const char *f, ...)
{
    int ret;
    va_list args;

/* TODO: buffer overflow */
    va_start(args, f);
    ret = vsprintf(m->buf + seq_file_idx, f, args);
    va_end(args);
    seq_file_idx += ret;
    ASSERT(seq_file_idx < MAX_PROC_BUF);
    return ret;
}
