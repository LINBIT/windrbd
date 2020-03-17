#ifndef _SIGNAL_H
#define _SIGNAL_H

struct task_struct;

extern int signal_pending(struct task_struct *p);
extern void force_sig(int sig, struct task_struct *p);
extern void send_sig(int sig, struct task_struct *p, int priv);
extern void flush_signals(struct task_struct *p);

#endif

