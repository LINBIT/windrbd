# run as root on a Linux host port is hardcoded to 7600
i=0
while true
do 
	i=$[ $i+1 ]
	echo "network failure $i"
	echo "about to drop packets"
	./iptables-drop.sh
	sleep 20
	echo "about to not drop packets"
	./iptables-dont-drop.sh
	sleep 20
done
