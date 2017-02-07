#!/bin/bash

FILE=$(mktemp)

echo "
@@
identifier func;
@@
func(...) {
+     KIRQL rcu_flags;
      <+...
-     rcu_read_lock();
+     rcu_flags = rcu_read_lock();
      ...
-     rcu_read_unlock();
+     rcu_read_unlock(rcu_flags);
      ...+>
 }
" > $FILE

spatch --sp-file $FILE --no-show-diff --in-place "$@"

rm $FILE
