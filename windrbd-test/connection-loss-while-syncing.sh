i=0
while true
do
	i=$[ $i+1 ]
	echo "Connection loss while syncing $i"
	sudo drbdadm up w0
	sleep 10
	sudo drbdadm invalidate w0
	sleep 2
	sudo drbdadm down w0
done
