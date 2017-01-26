#!/bin/bash


perl -i.bak -pe '

# BVD => ->
s/\s+BVD\s+/->/g;

# In 
#   #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt  
# coccinelle doesn´t like KBUILD_MODNAME
s/^.define pr_fmt.*\sKBUILD_MODNAME/#define pr_fmt(fmt) ":" fmt/;

# collapse lines
# s/\\\r?\n$/ /g; ## doesn´t help

' "$@"


