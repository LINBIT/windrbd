sudo iptables -D INPUT -p tcp --destination-port 7600 -j DROP
sudo iptables -D INPUT -p tcp --source-port 7600 -j DROP
sudo iptables -D OUTPUT -p tcp --destination-port 7600 -j DROP
sudo iptables -D OUTPUT -p tcp --source-port 7600 -j DROP
