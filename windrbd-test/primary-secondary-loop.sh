#!/bin/bash -x
i=0
while true
do
	i=$[ $i+1 ]
	echo Primary/Secondary $i
	drbdadm primary w0
	drbdadm secondary w0
	sleep 1
done
