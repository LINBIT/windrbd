i=0
while true
do 
	i=$[ $i+1 ]
	echo "Up / Sync a bit / Down $i ..."
	date

	drbdadm up reactos2
	drbdadm status
	drbdadm wait-connect reactos2
	drbdadm status
	sleep 30
	drbdadm status
	drbdadm down reactos2
	drbdadm status
done
