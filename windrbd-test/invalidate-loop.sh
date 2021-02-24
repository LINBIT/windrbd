#!/bin/bash

RES=w2
i=0
while true
do
	i=$[ $i+1 ]
	echo Invalidate $i
	drbdadm invalidate $RES
	drbdsetup --statistics status $RES
	sleep 5
	drbdsetup --statistics status $RES
#	time drbdadm wait-sync $RES
#	drbdsetup --statistics status $RES
#	sleep 5
#	drbdsetup --statistics status $RES
done
