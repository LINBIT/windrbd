#!/bin/bash

perl -i.bak -pe 's/\s__must_hold\(.*?\)(\s)$/$1/' "$@"


