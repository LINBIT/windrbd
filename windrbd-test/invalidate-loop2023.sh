RES=invalidate-test
i=0

time drbdadm up $RES
while true
do
	i=$[ $i+1 ]
	echo Invalidate $i
	date
	time drbdadm invalidate $RES
	drbdadm status $RES
	time drbdadm wait-sync $RES
	sleep 1
done
