#!/bin/sh

echo $1 | egrep "lru_cache.c" && (sed -ie '/WARN_ON(cache_obj_size < e_size);/,+3d' $1 && sed -ie '/cache_obj_size/d' $1)
exit 0
