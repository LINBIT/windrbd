i=0
while /bin/true
do
	i=$[ $i+1 ]
	echo Flush $i
	cp /dev/urandom /cygdrive/h/data
	./windrbd-test --gtest_filter=win_drbd.flush_disk
done
