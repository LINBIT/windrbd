i=0
while true
do 
	i=$[ $i+1 ]
	echo "Disconnect / Connect / Sync a bit $i ..."
	date

	drbdadm disconnect reactos2
	drbdadm status
	drbdadm connect reactos2
	drbdadm status
	drbdadm wait-connect reactos2
	drbdadm status
	sleep 30
	drbdadm status
done
