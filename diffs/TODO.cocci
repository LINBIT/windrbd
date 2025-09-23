Done: identifiers created by cocci should have __cocci_ prefix.
	Check

Cocci patches (generic unless noted otherwise):

Done: RCUs need a flag since they change the IRQ level in WinDRBD.

Done: Spinlocks that are locked and unlocked within the same function must be spin_lock_irqsave / spin_unlock_irqrestore.
	Must be able to handle multiple spinlocks in function
	(with 2 different flags). Also must be aware that
	the flags parameter might already be defined.

Rejected: The flag for the IRQ level should be of type KIRQL
	Hmm ... don't want this really

Done: replace all unsigned long -> ULONG_PTR and long -> LONG_PTR
also in macros
	TODO: only for 64 bit ...

TODO: Change UL postfix to ULL (64 bit only)
	We need this! Had a comparition:
		if (tmp == -1UL)
	failed when tmp is 64 bit (ULONG_PTR)
	Update: we have it, but ugly. Rewrite in sed using
	regexp!
	Only for 64 bit! (else syncing fails on 32 bit)

TODO: Also change %l[du] to %ll[du] in strings but ONLY
	for 64 bit!

Rejected: GNU extension: Change a?:b to a?a:b

Rejected: GNU extension: Change struct x y = { }; initializer to { 0 }

Rejected: GNU extension: Change sizeof(*p) to sizeof(*(char*)p) for void* p
	also for iov.iov_base += rv -> iov.iov_base = ((char*) iov.iov_base) + rv;
	(maybe (char*) iov.iov_base += rv also works ...)

Rejected: GNU extension: Change rv = wait_event_xxx(a, b, ...) to wait_event_xxx(rv, a, b)
	reason is: We don't have ({ ... }) in MS VC
	return value is ignored create a tmp variable (of which type?)

Rejected: GNU extension: no typeof so change hlist_for_each_entry(a, b, ..) to hlist_for_each_entry(struct x, a, b, ..) 
	where x is the type of a
	for all list_xxx macro calls

Rejected: GNU extension: In macro definitions use __VA_ARGS_
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

Rejected: MS VC: try and expect are reserved words.
	Check if this is true ...
	It looks like some header defines try as __try or so ...
	Now using SEH2_xx macros from ReactOS

Rejected: GNU extension: if (wait_ ...) (one occurence in drbd_state.c)
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

