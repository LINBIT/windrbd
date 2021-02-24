#!/bin/bash -x

RES=${RES:-w0}
i=0
while true
do
	i=$[ $i+1 ]
	date
	echo Disconnect $RES $i
	drbdadm disconnect $RES
	drbdadm status
	sleep 3
	drbdadm status
# TODO: not needed any more?
	drbdadm attach $RES
	drbdadm status
	echo Connect $RES $i
	drbdadm connect $RES
	drbdadm status
	drbdadm wait-connect $RES
	drbdadm status
	sleep 3
	drbdadm status
done
