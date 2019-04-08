#!/bin/bash -e

RES=${RES:-vamp-2nodes}
i=0
while true
do
	i=$[ $i+1 ]
	echo Detach $i
	drbdadm detach $RES
	sleep 5
	echo Attach $i
	drbdadm attach $RES
	echo Waitsync $i
	drbdadm wait-sync $RES
	echo Synced $i
	sleep 1
done
