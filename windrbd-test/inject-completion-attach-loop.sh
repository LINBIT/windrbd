#!/bin/bash -e

RES=w0
DRIVE=j:
i=0
echo "An I/O load should be put on the primary resource for this test to make sense"
while true
do
	i=$[ $i+1 ]
	echo Inject faults $i

# when this is used there is no sync after attach:
	# windrbd inject-faults 50 all-request
	windrbd inject-faults 50 all-completion
# with this there is a sync after attach:
#	windrbd inject-faults 50 backing-request
#	windrbd inject-faults 50 backing-request $DRIVE
	drbdadm status
	sleep 10
	drbdadm status
	windrbd inject-faults -1 all-completion
#	windrbd inject-faults -1 all-request

	drbdadm attach $RES
	drbdadm status
	sleep 3
	drbdadm status
	drbdadm wait-sync $RES
	drbdadm status
done
