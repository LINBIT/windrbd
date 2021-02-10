#!/bin/bash

RES=w0
i=0
while true
do
	i=$[ $i+1 ]
	echo Disconnect $i
	drbdadm disconnect $RES
	drbdadm status $RES
	sleep 10
	drbdadm status $RES
#	echo Disconnect \#2 $i
#	drbdadm disconnect $RES
#	drbdadm status
#	sleep 10
	echo Connect $i
	drbdadm connect $RES
	drbdadm status $RES
	drbdadm wait-connect $RES
	drbdadm status $RES
	echo Connected $i
	sleep 2
	drbdadm status $RES
done
