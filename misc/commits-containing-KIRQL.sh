for i in $( grep -l KIRQL * 2>/dev/null ) ; do git blame $i | grep KIRQL ; done | cut -d' ' -f1 | sort | uniq
