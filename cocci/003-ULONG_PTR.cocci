@@
identifier I;
@@
<...
-  unsigned long I;
+  ULONG_PTR I;
...>

@@
identifier I;
expression E;
@@
<...
-  unsigned long I = E;
+  ULONG_PTR I = E;
...>

/*
@ funcret @
identifier F;
@@
- unsigned long F(...) { ... }
+ ULONG_PTR F(...) { ... }
*/

@ funcparams @
identifier P;
identifier F;
@@
  F(
  ...,
- unsigned long P
+ ULONG_PTR P
  ,...
  ) { ... }
