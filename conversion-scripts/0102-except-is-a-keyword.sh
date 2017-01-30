#!/usr/bin/perl -pi.bak

s/([^\w\s]\s*except\b)/\1_/g;

# drbd_nl.c: +#define try try_val

s/(\btry\b)/\1_/g;
