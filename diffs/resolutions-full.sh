for i in remove cocci header compat manual upstream review
do
	echo -n "${i}: " > $i.resolution
	# grep ^\! *.[hc].diff | grep $i | sort | uniq >> $i.resolution
	grep -h ^\! *.[hc].diff | grep $i | sort | uniq >> $i.resolution
done
