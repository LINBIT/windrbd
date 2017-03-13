#!/usr/bin/perl -pi.bak

# BVD => ->
s/\s+BVD\s+/->/g;

# In
#   #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
# coccinelle doesn´t like KBUILD_MODNAME
s/^.define pr_fmt.*\sKBUILD_MODNAME.*/#define pr_fmt(fmt) ":" fmt/;

s/\s__printf\([ 0-9,]+\)\s/ /g;

# collapse lines
# s/\\\r?\n$/ /g; ## doesn´t help



