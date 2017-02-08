#!/usr/bin/perl -pi.bak

# - resync_lru = lc_create("resync", drbd_bm_ext_cache,
# + resync_lru = lc_create("resync", &drbd_bm_ext_cache,

s{
	( \s lc_create \( "\w+", ) \s*
}{ 
    "$1&"
}xe;

