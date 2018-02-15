i=0
while true
do
	i=$[ $i+1 ]
	echo Up/Down $i
	drbdadm up w0
	drbdadm down w0
	sleep 1
done
