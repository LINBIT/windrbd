for i in cygwin-binaries/*
do
	name=`basename $i`
	from=`which $name`
	echo "$from -> $i ..."
	cp $from $i
done
