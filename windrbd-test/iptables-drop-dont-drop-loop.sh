# run as root on a Linux host port is hardcoded to 7600
i=0
while true
do 
	i=$[ $i+1 ]
	echo "network failure $i"
	./iptables-drop.sh
	sleep 20
	./iptables-dont-drop.sh
	sleep 20
done
