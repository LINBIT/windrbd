grep "IoCtl request not im" /var/log/syslog | cut -d ' ' -f 14- | sort | uniq
