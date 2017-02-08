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
