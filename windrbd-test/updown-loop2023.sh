RES=large1
i=0
while true
do
	i=$[ $i+1 ]
	echo Up/Down $i
	date
	time drbdadm up $RES
	time drbdadm down $RES
	sleep 1
done
