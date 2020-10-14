#!/bin/bash
# Meant to test n>2 nodes connect 
i=0
while true
do
	i=$[ $i+1 ]
	echo Down/Up/Reconnect $i

	echo Down
	time drbdadm down w2
	echo Up
	time drbdadm up w2
	date
	drbdadm status w2 
	echo Wait-connect
	time drbdadm wait-connect w2
	date
	drbdadm status w2
done
