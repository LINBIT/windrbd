#!/bin/bash -x
# Run this test on Windows side.
# must have ssh key installed on Linux side
# must have sudo passwordless set (edit /etc/sudoers:
# %sudo   ALL=(ALL) NOPASSWD:ALL
#
LINUX=johannes@192.168.56.102
RES=w0
j=0

while true
do
j=$[ $j+1 ]
echo Data coherence test $j

for i in 1 2 3 4
do
	ssh $LINUX sudo drbdadm primary $RES
	ssh $LINUX sudo kpartx /dev/drbd26 -a
	ssh $LINUX sudo mount /dev/dm-0 ~/Linbit/tmp/mnt

	ssh $LINUX rm ~/Linbit/tmp/mnt/random-30megs*
	ssh $LINUX cp ~/Linbit/tmp/random-30megs-$i ~/Linbit/tmp/mnt

	ssh $LINUX sudo umount ~/Linbit/tmp/mnt 
	ssh $LINUX sudo kpartx /dev/drbd26 -d
	ssh $LINUX sudo drbdadm secondary $RES

	drbdadm primary $RES
	sleep 3
	diff /cygdrive/y/tmp/random-30megs-$i /cygdrive/p/random-30megs-$i
	if [ $? -ne 0 ] ; then
		echo "Data not coherent."
		exit 1
	fi
	drbdadm secondary $RES
done
done
