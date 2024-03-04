#ifndef ATOMIC_H
#define ATOMIC_H

#define	atomic_inc_return(_p)		InterlockedIncrement((LONG volatile*)(_p))
#define	atomic_dec_return(_p)		InterlockedDecrement((LONG volatile*)(_p))
#define atomic_inc(_v)			atomic_inc_return(_v)
#define atomic_dec(_v)			atomic_dec_return(_v)

#endif
