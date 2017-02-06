#!/usr/bin/perl -pi.bak

# remove definition
s/\#\s*define\s*__must_hold.*//;

s/[\s)]__must_hold\(.*?\)([\s;]+)$/$1/;


