@@
identifier func;
expression lock;
@@
func(...) {
+     KIRQL spin_lock_irq_flags;
      <+...
-     spin_lock_irq(lock);
+     spin_lock_irqsave(lock, spin_lock_irq_flags);
      ...
-     spin_unlock_irq(lock);
+     spin_unlock_irqrestore(lock, spin_lock_irq_flags);
      ...+>
 }
@@
identifier func;
expression lock;
@@
func(...) {
+     KIRQL spin_lock_flags;
      <+...
-     spin_lock(lock);
+     spin_lock_irqsave(lock, spin_lock_flags);
      ...
-     spin_unlock(lock);
+     spin_unlock_irqrestore(lock, spin_lock_flags);
      ...+>
 }
