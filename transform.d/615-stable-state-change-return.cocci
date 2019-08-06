@@
identifier func;
expression list E;
@@
func(...) {
+     int __ret;
      <+...
(
-     return stable_state_change(E);
+     stable_state_change(__ret, E);
+     return __ret;
)
      ...+>
}

@@
identifier t;
expression list E;
@@
-     t = stable_state_change(E)
+     stable_state_change(t, E)
