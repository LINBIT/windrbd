#ifndef ATOMIC_H
#define ATOMIC_H

#include <linux/types.h>

#ifdef _WIN64
#define xchg(target, value) \
	(void*) InterlockedExchange64((LONG_PTR*) target, (LONG_PTR) value)
#else
#define xchg(target, value) \
	(void*) InterlockedExchange((LONG_PTR*) target, (LONG_PTR) value)
#endif

extern void atomic_set(atomic_t *v, int i);
extern void atomic_add(int i, atomic_t *v);
extern int atomic_add_return(int i, atomic_t *v);
extern void atomic_sub(int i, atomic_t *v);
extern int atomic_sub_return(int i, atomic_t *v);
extern int atomic_dec_and_test(atomic_t *v);
extern int atomic_sub_and_test(int i, atomic_t *v);
extern int atomic_cmpxchg(atomic_t *v, int old, int new);
extern int cmpxchg(ULONG_PTR *v, int old, int new);
extern int atomic_read(const atomic_t *v);
extern int atomic_xchg(atomic_t *v, int n);

#define	atomic_inc_return(_p)		InterlockedIncrement((LONG volatile*)(_p))
#define	atomic_dec_return(_p)		InterlockedDecrement((LONG volatile*)(_p))
#define atomic_inc(_v)			atomic_inc_return(_v)
#define atomic_dec(_v)			atomic_dec_return(_v)

/* TODO: Atomic64 .. they should go somewhere else (atomic64.h)? */

        /* TODO: are these really atomic? */
static inline s64 atomic64_read(const atomic64_t *v)
{
        return v->counter;
}

static inline void atomic64_set(atomic64_t *v, s64 val)
{
	v->counter = val;
}

#define	atomic64_inc_return(_p)		InterlockedIncrement64((long long volatile*)(&(_p)->counter))
#define	atomic64_dec_return(_p)		InterlockedDecrement64((long long volatile*)(&(_p)->counter))

#endif
