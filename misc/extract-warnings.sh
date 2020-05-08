grep 'warning C' makelog | sed -e 's/^.*C\([0-9]*\).*$/\1/g' | sort | uniq

