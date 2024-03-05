@@
identifier i;
@@
-    unsigned long i;
+    ULONG_PTR i;
@@
identifier i;
identifier func;
@@
func(...) {
     <+...
-        unsigned long i;
+        ULONG_PTR i;
     ...+>
 }
@@
identifier i;
identifier func;
@@
- func(unsigned long i)
+ func(ULONG_PTR i)
@@
identifier i;
identifier func;
@@
- func(..., unsigned long i, ...) {
+ func(ULONG_PTR i) {
     ...
 }
@@
identifier i;
identifier func;
@@
-func(..., unsigned long *i, ...) {
+func(ULONG_PTR *i) {
     ...
 }
