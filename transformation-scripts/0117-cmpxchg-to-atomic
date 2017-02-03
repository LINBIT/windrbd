#!/usr/bin/perl -pi.bak

sub BEGIN {
	$/ = ';';
}

# rck> | #ifdef _WIN32
# rck> |                 val = atomic_cmpxchg((atomic_t *)&lc->flags, 0, LC_LOCKED);
# rck> | #else
# rck> |                 val = cmpxchg(&lc->flags, 0, LC_LOCKED);
# rck> | #endif


s{ (?<call> \b cmpxchg\( )
	(?<arg1> [^,]+  ) ,
	(?<arg2> [^,]+  ) ,
	(?<arg3> [^)]+ ) \)
}{
	"atomic_cmpxchg((atomic_t*)($+{arg1}),$+{arg2},$+{arg3})"
}ex;
