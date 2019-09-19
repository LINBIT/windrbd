if [ $# -ne 1 ] ; then
	echo "Usage: $0 <port>"
	exit 1
fi

PORT=$1
sudo iptables -D INPUT -p tcp --destination-port $PORT -j DROP
sudo iptables -D INPUT -p tcp --source-port $PORT -j DROP
sudo iptables -D OUTPUT -p tcp --destination-port $PORT -j DROP
sudo iptables -D OUTPUT -p tcp --source-port $PORT -j DROP
