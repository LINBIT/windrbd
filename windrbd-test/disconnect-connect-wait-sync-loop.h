#!/bin/bash -e

RES=w0
i=0
while true
do
	i=$[ $i+1 ]
	echo Disconnect $i
	drbdadm disconnect $RES
	drbdadm status
	sleep 20
	echo Connect $i
	drbdadm connect $RES
	echo Connected $i
	drbdadm status
	drbdadm wait-sync $RES
	echo Synced $i
	drbdadm status
	sleep 1
done
