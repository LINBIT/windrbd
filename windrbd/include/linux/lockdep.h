#ifndef __LOCKDEP_H
#define __LOCKDEP_H

/* TODO: It actually makes sense to implement them one day: */
/* Must reference x else more warnings ... */

#define lockdep_assert_held(x) (void)(x)
#define lockdep_assert_irqs_disabled() do { } while (0);

#endif
