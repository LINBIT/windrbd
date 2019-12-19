# run as root on a Linux host port is hardcoded to 7600
i=0
while true
do 
	i=$[ $i+1 ]
	echo "network failure $i"
	echo "about to drop packets"
	./iptables-drop.sh
	sleep 10
	drbdadm status
	echo "about to not drop packets"
	./iptables-dont-drop.sh
	sudo drbdadm wait-sync w0
	sleep 2
	drbdadm status
done
