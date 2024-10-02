i=0
while true
do
	i=$[ $i+1 ]
	echo Primary/Secondary $i ...
	drbdadm primary reactos2
	drbdadm status
#	sleep 5
	drbdadm secondary reactos2
	drbdadm status
#	sleep 5
done
	
