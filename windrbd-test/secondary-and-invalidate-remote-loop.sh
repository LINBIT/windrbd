#!/bin/bash
i=0
while true
do
	i=$[ $i+1 ]
	echo Secondary $i
	drbdadm secondary w0
	drbdadm status
	sleep 5
	echo Invalidating remote $i
	drbdadm invalidate-remote w0
	drbdadm status
	sleep 3
	drbdadm status
	drbdadm wait-sync w0
	drbdadm status
	echo Primary $i
	drbdadm primary w0
	drbdadm status
	sleep 10
done
