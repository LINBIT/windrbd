#!/bin/bash
i=0
while true
do
	i=$[ $i+1 ]
	echo "Down $i"
	sudo drbdadm down w0
	echo "Up $i"
	sudo drbdadm up w0
	drbdadm status
	echo "Waiting for sync $i"
	sudo time drbdadm wait-sync w0
	drbdadm status
	sleep 1
done
