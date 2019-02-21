RES=${RES:-w0}
i=0
while true
do
	drbdadm up $RES
	sleep 2
	drbdadm down all
	sc stop windrbdumhelper
	sc stop windrbdlog
	sc stop windrbd
	sc query windrbd
done
