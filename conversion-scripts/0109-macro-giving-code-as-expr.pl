#!/usr/bin/perl -pi.bak


# -   ({ if (last_func) \
# +   { if (last_func) \

s/\(\{/{/g;
s/\}\)/}/g;
