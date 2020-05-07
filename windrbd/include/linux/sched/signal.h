#ifndef _SIGNAL_H
#define _SIGNAL_H

struct task_struct;

extern int signal_pending(struct task_struct *p);
extern void force_sig(int sig, struct task_struct *p);
extern void send_sig(int sig, struct task_struct *p, int priv);
extern void flush_signals(struct task_struct *p);

static inline void allow_kernel_signal(int sig)
{
	/*
	 * Kernel threads handle their own signals. Let the signal code
	 * know signals sent by the kernel will be handled, so that they
	 * don't get silently dropped.
	 */
	/* No action in WinDRBD */
}

#endif

