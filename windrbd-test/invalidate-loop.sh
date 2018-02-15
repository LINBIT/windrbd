i=0
while true
do
	i=$[ $i+1 ]
	echo Invalidate $i
	drbdadm invalidate w0
	sleep 60
done
