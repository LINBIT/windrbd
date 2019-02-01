#!/bin/bash

i=0
while true
do
	i=$[ $i+1 ]
	echo Disconnect $i
	drbdadm disconnect w0
	sleep 5
	echo Connect $i
	drbdadm connect w0
	sleep 5 
done
