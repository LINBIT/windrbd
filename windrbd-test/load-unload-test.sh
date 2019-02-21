#!/bin/bash

RES=${RES:-w0}
i=0
while true
do
	i=$[ $i+1 ]
	echo "Load/Unload $i"
# Currently BSODs with this:
#	drbdadm up $RES
# No BSOD with this (10 minutes test)
#	drbdadm status
# Now trying with disk only (no connect)
	drbdsetup new-resource w0 2
	drbdsetup new-minor w0 5 17
	drbdmeta 5 v09 G: flex-external apply-al
	drbdsetup attach 5 F: G: flexible
	drbdadm status

	sleep 2
	drbdadm down all
	sc stop windrbdumhelper
	sc stop windrbdlog
	sc stop windrbd
	sc query windrbd
done
