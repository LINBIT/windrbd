#!/bin/bash

RES=w0
i=0
while true
do
	i=$[ $i+1 ]
	echo Disconnect $i
	drbdadm disconnect $RES
	sleep 10
	echo Connect $i
	drbdadm connect $RES
	sleep 10
done
