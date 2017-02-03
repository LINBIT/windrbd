#!/usr/bin/perl -pi.bak

# remove definition
s/\#\s*define\s*__must_hold.*//;

s/\s__must_hold\(.*?\)([\s;]+)$/$1/;


