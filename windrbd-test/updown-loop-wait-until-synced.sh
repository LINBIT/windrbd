i=0
while true
do
	i=$[ $i+1 ]
	echo 'Up/Down $i'
	sudo drbdadm down w0
	sleep 10
	sudo drbdadm up w0
	sleep 10
done
