i=0
while true
do
	i=$[ $i+1 ]
	echo Invalidating remote $i
	drbdadm invalidate-remote w0
	sleep 5
done
