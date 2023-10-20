MINOR=2
RES=test-16tb
FIO=/home/Administrator/fio-3.27-x64/fio

drbdadm up $RES
drbdadm primary --force $RES

i=0
failed=0
while true
do
	i=$[ $i+1 ]
	echo "Disk timeout $i ($failed failed) ..."
	date

	drbdsetup disk-options $MINOR --set-defaults --disk-timeout=1
	$FIO  --name=i:test-123 --size=1000m --rw=randrw --direct=1 --bs=4k --numjobs=1 --iodepth=1000
	if [ $? -ne 0 ] ; then
		echo "I/O failed"
		drbdadm status $RES
		failed=$[ $failed+1 ]
#		exit 1
	fi
	drbdadm secondary $RES
# failed? with I/O error on meta data access
	drbdadm adjust $RES
#	drbdadm down $RES
#	drbdadm up $RES

#	drbdsetup disk-options $MINOR --set-defaults --disk-timeout=0

#	drbdadm secondary $RES
	drbdadm primary $RES --force
done
