#ifndef _ASM_SIGNAL_H
#define _ASM_SIGNAL_H

#define _NSIG		64

#ifdef CONFIG_64BIT
# define _NSIG_BPW	64
#else
# define _NSIG_BPW	32
#endif

#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef ULONG_PTR old_sigset_t;		/* at least 32 bits */

typedef struct {
	ULONG_PTR sig[_NSIG_WORDS];
} sigset_t;


static inline void sigfillset(sigset_t *set)
{
	switch (_NSIG_WORDS) {
	default:
		memset(set, -1, sizeof(sigset_t));
		break;
	case 2: set->sig[1] = -1;
		fallthrough;
	case 1:	set->sig[0] = -1;
		break;
	}
}

static inline void sigorsets(sigset_t *res, sigset_t *a, sigset_t *b)
{
	switch (_NSIG_WORDS) {
	case 2: res->sig[1] = a->sig[1] | b->sig[1];
		fallthrough;
	case 1:	res->sig[0] = a->sig[0] | b->sig[0];
	}
}

	/* TODO: b negated or not? */
static inline void sigandnsets(sigset_t *res, sigset_t *a, sigset_t *b)
{
	switch (_NSIG_WORDS) {
	case 2: res->sig[1] = a->sig[1] & ~b->sig[1];
		fallthrough;
	case 1:	res->sig[0] = a->sig[0] & ~b->sig[0];
		break;
	}
}

#ifndef SIG_BLOCK
#define SIG_BLOCK          0	/* for blocking signals */
#endif
#ifndef SIG_UNBLOCK
#define SIG_UNBLOCK        1	/* for unblocking signals */
#endif
#ifndef SIG_SETMASK
#define SIG_SETMASK        2	/* for setting the signal mask */
#endif

extern int sigprocmask(int, sigset_t *, sigset_t *);

#define SIGHUP					1
#define SIGINT					2
#define SIGCHLD					17
#define SIGXCPU					24

#endif
