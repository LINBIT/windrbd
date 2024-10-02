i=0
while true
do 
	i=$[ $i+1 ]
	echo "Invalidate / WaitSync $i ..."
	date

	drbdadm invalidate reactos2
	drbdadm status
	time drbdadm wait-sync reactos2
	drbdadm status
	sleep 5
	drbdadm status
done
