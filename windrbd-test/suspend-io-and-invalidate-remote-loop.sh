#!/bin/bash
i=0
while true
do
	i=$[ $i+1 ]
	echo Suspending I/O $i
	drbdadm suspend-io w0
	drbdadm status
	sleep 5
	echo Invalidating remote $i
	drbdadm invalidate-remote w0
	drbdadm status
	sleep 3
	drbdadm status
	drbdadm wait-sync w0
	drbdadm status
	echo Resuming I/O $i
	drbdadm resume-io w0
	drbdadm status
	sleep 5
done
