#!/bin/bash -e

RES=w0
i=0
echo "An I/O load should be put on the primary resource for this test to make sense"
while true
do
	i=$[ $i+1 ]
	echo Inject faults $i

	windrbd inject-faults 50 all-request
	drbdadm status
	sleep 10
	drbdadm status
	windrbd inject-faults -1 all-request

	drbdadm attach $RES
	drbdadm status
	drbdadm wait-sync $RES
	drbdadm status
done
