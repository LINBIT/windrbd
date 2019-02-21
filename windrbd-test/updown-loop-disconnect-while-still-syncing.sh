#!/bin/bash
i=0
RES=vamp-2nodes

# When not letting sync finish, Windows Server 2016 freezes
# (after 2200 iterations of write-fs-loop)

while true
do
	i=$[ $i+1 ]
	echo "Down $i"
	drbdadm down $RES
	sleep 10
	echo "Up $i"
	drbdadm up $RES
	echo "Up finished $i"
	drbdadm wait-connect $RES
	echo "Connected $i"
#	drbdadm wait-sync $RES
#	echo "Waiting for sync finished $i"
#	sleep 5
	sleep 3
done
