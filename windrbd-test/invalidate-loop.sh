#!/bin/bash

i=0
while true
do
	i=$[ $i+1 ]
	echo Invalidate $i
	drbdadm invalidate w0
	drbdsetup --statistics status
	sleep 3
	drbdsetup --statistics status
	sleep 10
	drbdadm wait-sync w0
	drbdsetup --statistics status
	sleep 20
	drbdsetup --statistics status
done
