#!/bin/bash

RES=${RES:-w0}
i=0

while true
do
	i=$[ $i+1 ]
	echo Loop $i
	drbdadm up $RES
	echo Up $i
	drbdadm wait-connect $RES
	echo Connected $i
	sleep 1
	drbdadm down $RES
	echo Down $i
	sleep 1
done
