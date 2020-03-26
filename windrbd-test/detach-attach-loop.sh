#!/bin/bash -e

RES=${RES:-w0}
i=0
while true
do
	i=$[ $i+1 ]
	echo Detach $i
	drbdadm detach $RES
	sleep 5
	echo Attach $i
	drbdadm attach $RES
	sleep 5
done
