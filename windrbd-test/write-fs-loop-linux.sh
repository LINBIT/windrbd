#!/bin/bash

i=0
while true
do
	i=$[ $i+1 ]
	echo Write File $i
#	cp /dev/zero /home/johannes/Linbit/tmp/mnt/data
	time (
		# dd if=/dev/zero of=/home/johannes/Linbit/tmp/mnt/data bs=$[ 1024*1024 ] count=30
#		dd if=/dev/zero of=/home/johannes/Linbit/tmp/mnt/data bs=$[ 1024 ] count=$[ 30 * 1024 ]
		dd if=/dev/zero of=/home/johannes/Linbit/mnt/data bs=$[ 1024 ] count=$[ 30 * 1024 ]
		sync
	)
	date
done
