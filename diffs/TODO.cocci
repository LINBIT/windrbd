identifiers created by cocci should have __cocci_ prefix.

Cocci patches (generic unless noted otherwise):

TODO: RCUs need a flag since they change the IRQ level in WinDRBD.

TODO: Spinlocks that are locked and unlocked within the same function must be spin_lock_irqsave / spin_unlock_irqrestore.
	Must be able to handle multiple spinlocks in function
	(with 2 different flags). Also must be aware that
	the flags parameter might already be defined.

TODO: The flag for the IRQ level should be of type KIRQL

TODO: replace all unsigned long -> ULONG_PTR and long -> LONG_PTR
also in macros

TODO: Change UL postfix to ULL (64 bit only)

TODO: GNU extension: Change a?:b to a?a:b

TODO: GNU extension: Change struct x y = { }; initializer to { 0 }

TODO: GNU extension: Change sizeof(*p) to sizeof(*(char*)p) for void* p
	also for iov.iov_base += rv -> iov.iov_base = ((char*) iov.iov_base) + rv;
	(maybe (char*) iov.iov_base += rv also works ...)

TODO: GNU extension: Change rv = wait_event_xxx(a, b, ...) to wait_event_xxx(rv, a, b)
	reason is: We don't have ({ ... }) in MS VC
	return value is ignored create a tmp variable (of which type?)

TODO: DRBD specific (and GNU extension): Change rv = stable_state_change(a, b, ...) to stable_state_change(rv, a, b, ...)

TODO: GNU extension: no typeof so change hlist_for_each_entry(a, b, ..) to hlist_for_each_entry(struct x, a, b, ..) 
	where x is the type of a
	for all list_xxx macro calls

TODO: GNU extension: In macro definitions use __VA_ARGS_
	#define A(x, args...)
		## args ##
	#define A(x)
		## __VA_ARGS_ ##

Rejected: GNU extension: In macro definitions replace
	#define A(a, b, c) ({
		do_something();
		return_value;
		})
	by
	#define A(__cocci_retval, a, b, c) (
		sometype __cocci_retval;
		do_something();
		__cocci_retval = return_value;
		)
	Rejected becaue there are many different uses of
	({ ... })

TODO: MS VC: try and expect are reserved words.
	Check if this is true ...
	It looks like some header defines try as __try or so ...

TODO: GNU extension: if (wait_ ...) (one occurence in drbd_state.c)
			x;
		by
		LONG_PTR __cocci_t;
		wait_(__cocci_t, ...)
		if (__cocci_t)
			x;

Rejected: Maybe cocci (but only one spinlock ... fix that first)
        Also used in abort_local_transaction()
        Can inter-function flag passing patched by cocci?

Rejected: manual (cocci cannot find type - maybe by _resource macro name?)
	in drbd_int.h - we should not derive types from variable names ...

