i=100
while true
do 
	date
#	make USE_CLANG=1 -j16 install TARGET_IPS='10.43.208.80 10.43.208.81 10.43.208.82' VERSION=crash-on-cannot-update$i
	make -j16 install TARGET_IPS='10.43.208.80 10.43.208.81 10.43.208.82' VERSION=crash-on-cannot-update$i
	sleep 60
	i=$[ $i+1 ]
done
