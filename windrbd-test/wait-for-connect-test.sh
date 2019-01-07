#!/bin/bash
i=0

while true
do
	i=$[ $i+1 ]
	echo "diconnect / connect / wait-for-connect $i"
	drbdadm disconnect w0
	drbdadm connect w0
	drbdsetup wait-connect-resource w0
	c=`drbdadm cstate w0`
	if [ $c != Connected ]
	then
		echo "state is $c"
		drbdadm status
#		break
	fi
done
drbdadm status

