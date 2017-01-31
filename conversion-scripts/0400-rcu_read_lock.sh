#!/bin/bash

FILE=$(mktemp)

echo "
@@
identifier func;
@@
func (...) {
+     unsigned long rcu_flags;
      ...
-     rcu_read_lock();
+     rcu_flags = rcu_read_lock();
      ...
 }

@@
identifier func;
@@
func (...) {
      ...
-     rcu_read_unlock();
+     rcu_read_unlock(rcu_flags);
      ...
 }
" > $FILE

spatch --sp-file $FILE --in-place "$@"

rm $FILE
