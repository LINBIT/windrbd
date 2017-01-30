#!/usr/bin/perl -pi.bak


# -   union drbd_state mask = {}, val = {};
# +   union drbd_state mask = { 0, };
# +   union drbd_state val = { 0, };
s( (= \s* \{) \s* \} )( "$1 0 }" )gx;

