#!/bin/bash

RES=w0
i=0
while true
do
	i=$[ $i+1 ]
	echo Disconnect $i
	drbdadm disconnect $RES
	drbdadm status
	sleep 10
	drbdadm status
#	echo Disconnect \#2 $i
#	drbdadm disconnect $RES
#	drbdadm status
#	sleep 10
	echo Connect $i
	drbdadm connect $RES
	drbdadm status
	drbdadm wait-connect $RES
	drbdadm status
	echo Connected $i
	sleep 3
	drbdadm status
done
