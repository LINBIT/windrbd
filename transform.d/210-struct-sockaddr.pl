#!/usr/bin/perl -pi.bak


# There _is_ a struct sockaddr_storage in windows, in ws2def.h.
# But trying to include that just leads from one macro name conflict to another.
s/\bstruct sockaddr_storage\b/struct sockaddr_storage_win/g;
