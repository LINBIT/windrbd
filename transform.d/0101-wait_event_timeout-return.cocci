@@
identifier func;
expression list E;
statement S1, S2;
@@
func(...) {
+     long remaining_time;
      <+...
-     if (wait_event_timeout(E)) S1 else S2
+     wait_event_timeout(remaining_time, E); if (remaining_time) S1 else S2
      ...+>
}

@@
identifier t;
expression list E;
@@
-     t = wait_event_interruptible_timeout(E)
+     wait_event_interruptible_timeout(t, E)

@@
identifier t;
expression list E;
@@
-     t = wait_event_timeout(E)
+     wait_event_timeout(t, E)
