#!/usr/bin/perl -pi.bak

# remove definition
s/#define\s__must_hold.*//;

s/\s__must_hold\(.*?\)([\s;]+)$/$1/;


