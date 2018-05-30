grep 'Resync done' /var/log/syslog | sed -e 's/.*total \([0-9][0-9]*\) sec.*/\1/g' | sort -n
