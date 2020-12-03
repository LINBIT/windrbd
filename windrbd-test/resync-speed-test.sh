#!/bin/bash

i=0
while true
do
	i=$[ $i+1 ]
	echo Resync $i
	drbdadm invalidate w0 
	time drbdadm wait-sync w0
done
