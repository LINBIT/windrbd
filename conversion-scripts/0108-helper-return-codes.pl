#!/usr/bin/perl -pi.bak


# +           r = r << 8;
#             r = (r >> 8) & 0xff;

sub BEGIN {
    undef $/;
}


s{\((\w+) \>\> 8\) \& 0xff}
 {$1}g;
