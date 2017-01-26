#!/bin/bash

perl -i.bak -pe '
s/([^\w\s]\s*except\b)/\1_/g;
' "$@"
