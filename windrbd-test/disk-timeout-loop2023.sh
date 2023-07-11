MINOR=2
RES=test-16tb
FIO=/home/Administrator/fio-3.27-x64/fio

i=0
while true
do
	i=$[ $i+1 ]
	echo "Disk timeout $i ..."

	drbdsetup disk-options $MINOR --set-defaults --disk-timeout=1
	$FIO  --name=i:test-123 --size=1000m --rw=randrw --direct=1 --bs=4k --numjobs=1 --iodepth=100
	if [ $? -ne 0 ] ; then
		echo "I/O failed"
		drbdadm status $RES
	fi
	drbdadm secondary $RES
# failed? with I/O error on meta data access
	drbdadm adjust $RES
#	drbdadm down $RES
#	drbdadm up $RES

#	drbdsetup disk-options $MINOR --set-defaults --disk-timeout=0

	drbdadm secondary $RES
	drbdadm primary $RES --force
done
