i=0
while true
do
	i=$[ $i+1 ]
	echo Disconnect/Connect $i
	drbdadm disconnect w0
	sleep 5
	drbdadm connect w0
	sleep 5 
done
