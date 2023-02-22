for i in remove cocci header compat manual upstream review
do
	echo -n "${i}: "
	grep -h ^\! *.c.diff | grep $i | sort | uniq | wc -l
done
