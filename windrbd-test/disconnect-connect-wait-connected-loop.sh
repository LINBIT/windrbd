#!/bin/bash -e

RES=w0
i=0
while true
do
	i=$[ $i+1 ]
	echo Disconnect $i
	drbdadm disconnect $RES
	sleep 5
	echo Connect $i
	drbdadm connect $RES
	drbdadm wait-connect $RES
	echo Connected $i
	sleep 1
done
