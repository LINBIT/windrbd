i=0
while true
do
	i=$[ $i+1 ]
	echo "Down $i"
	sudo drbdadm down w0
	sleep 10
	echo "Up $i"
	sudo drbdadm up w0
	sleep 10
done
