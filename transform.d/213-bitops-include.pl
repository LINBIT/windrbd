#!/usr/bin/perl -pi.bak

# - #include "drbd-kernel-compat/bitops.h"
# + #include "bitops.h"

s{
	^ \s* \# \s* include \s* .* bitops.h .*
}{ 
	"#include <linux/bitops.h>"
}xe;


