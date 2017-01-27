#!/bin/bash

# - 	t = wait_event_timeout(device->misc_wait,
# +    wait_event_timeout(t, device->misc_wait,

perl -i.bak -pe '
s/^(\s*(\w+)\s*=\s*list_first_or_null_rcu\()/$1$2, /;
' "$@"
