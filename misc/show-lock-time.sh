#!/bin/bash
# Show and sort log output of SPINLOCK_DEBUG2
# typical usage is:
# cat /var/log/syslog | ./show-lock-time.sh

grep 'locked by' | sed -e 's/.*locked by \([^)]*))\).*time is \([0-9]*\)/\2 \1/g' | sort -n

