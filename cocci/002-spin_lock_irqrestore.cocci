@@
identifier func;
expression lock;
expression lock2;
@@
func(...) {
+     KIRQL __cocci_spin_lock_irq_flags;
+     KIRQL __cocci_spin_lock_irq_flags2;
      <+...
-     spin_lock_irq(lock);
+     spin_lock_irqsave(lock, __cocci_spin_lock_irq_flags);
      <+...
-     spin_lock(lock2);
+     spin_lock_irqsave(lock2, __cocci_spin_lock_irq_flags2);
      ...
-     spin_unlock(lock2);
+     spin_unlock_irqrestore(lock2, __cocci_spin_lock_irq_flags2);
      ...+>
-     spin_unlock_irq(lock);
+     spin_unlock_irqrestore(lock, __cocci_spin_lock_irq_flags);
      ...+>
 }
@@
identifier func;
expression lock;
@@
func(...) {
+     KIRQL __cocci_spin_lock_irq_flags;
      <+...
-     spin_lock_irq(lock);
+     spin_lock_irqsave(lock, __cocci_spin_lock_irq_flags);
      ...
-     spin_unlock_irq(lock);
+     spin_unlock_irqrestore(lock, __cocci_spin_lock_irq_flags);
      ...+>
 }
@@
identifier func;
expression lock;
@@
func(...) {
+     KIRQL __cocci_spin_lock_flags;
      <+...
-     spin_lock(lock);
+     spin_lock_irqsave(lock, __cocci_spin_lock_flags);
      ...
-     spin_unlock(lock);
+     spin_unlock_irqrestore(lock, __cocci_spin_lock_flags);
      ...+>
 }
@@
identifier func;
expression lock;
@@
func(...) {
+     KIRQL __cocci_spin_lock_flags2;
      <+...
-     spin_lock_bh(lock);
+     spin_lock_irqsave(lock, __cocci_spin_lock_flags2);
      ...
-     spin_unlock_bh(lock);
+     spin_unlock_irqrestore(lock, __cocci_spin_lock_flags2);
      ...+>
 }
@@
identifier func;
expression lock;
@@
func(...) {
+     KIRQL __cocci_spin_lock_flags3;
      <+...
-     write_lock_bh(lock);
+     write_lock_irqsave(lock, __cocci_spin_lock_flags3);
      ...
-     write_unlock_bh(lock);
+     write_unlock_irqrestore(lock, __cocci_spin_lock_flags3);
      ...+>
 }
@@
identifier func;
expression lock;
@@
func(...) {
+     KIRQL __cocci_read_lock_flags;
      <+...
-     read_lock_irq(lock);
+     read_lock_irqsave(lock, __cocci_read_lock_flags);
      ...
-     read_unlock_irq(lock);
+     read_unlock_irqrestore(lock, __cocci_read_lock_flags);
      ...+>
 }
@@
identifier func;
expression lock;
@@
func(...) {
+     KIRQL __cocci_write_lock_flags;
      <+...
-     write_lock_irq(lock);
+     write_lock_irqsave(lock, __cocci_write_lock_flags);
      ...
-     write_unlock_irq(lock);
+     write_unlock_irqrestore(lock, __cocci_write_lock_flags);
      ...+>
 }
