#!/usr/bin/perl -pi.bak


# -   m->error = ok ? 0 : (error ?: -EIO);
# +   m->error = ok ? 0 : (error ? error : -EIO);

# -   timeout = (nc->sock_check_timeo ?: nc->ping_timeo) * HZ / 10;
# +   timeout = (nc->sock_check_timeo ? nc->sock_check_timeo : nc->ping_timeo) * HZ / 10;


# whitespace or parenthesis as separator; not really C conform, but works for our current code.

s{ (?<part1> [\s(] (?<cond> \S+ ) \s* ) \?\: }
 {
     "$+{part1}? $+{cond} : ";
 }xeg;

