#!/bin/sh

echo $1 | egrep "lru_cache.c" && (sed -ie 's/hlist_for_each_entry(\(.*\),\(.*\),\(.*\))/hlist_for_each_entry(struct lc_element,\1,\2,\3)/g' $1)
