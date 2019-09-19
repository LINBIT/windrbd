if [ $# -ne 1 ] ; then
	echo "Usage: $0 <port>"
	exit 1
fi

PORT=$1
sudo iptables -I INPUT 1 -p tcp --destination-port $PORT -j DROP
sudo iptables -I INPUT 1 -p tcp --source-port $PORT -j DROP
sudo iptables -I OUTPUT 1 -p tcp --destination-port $PORT -j DROP
sudo iptables -I OUTPUT 1 -p tcp --source-port $PORT -j DROP
