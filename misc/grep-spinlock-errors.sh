grep '(called from' /var/log/syslog | sed -e 's/.*called from \([^(]*\).*/\1/g' | sort | uniq
