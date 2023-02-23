Generic patches:

RCUs need a flag since they change the IRQ level in WinDRBD.

Spinlocks that are locked and unlocked within the same function
must be spin_lock_irqsave / spin_unlock_irqrestore.

The flag for the IRQ level should be of type KIRQL

replace all unsigned long -> ULONG_PTR and long -> LONG_PTR
also in macros

Change UL postfix to ULL (64 bit only)

GNU extension: Change a?:b to a?a:b

GNU extension: Change struct x y = { }; initializer to { 0 }

GNU extension: Change sizeof(*p) to sizeof(*(char*)p) for void* p

GNU extension: Change
	rv = wait_event_xxx(a, b, ...) to wait_event_xxx(rv, a, b)
	We don't have ({ ... }) in MS VC

DRBD specific: do the above also for stable_state_change

GNU extension: no typeof so change
	hlist_for_each_entry(a, b, ..) to hlist_for_each_entry(struct x, a, b, ..) 
	where x is the type of a
