#!/bin/bash

i=0
while true
do
	i=$[ $i+1 ]
	echo Write File $i
#	cp /dev/zero /home/johannes/Linbit/tmp/mnt/data
	dd if=/dev/zero of=/dev/drbd26 bs=$[ 1024*1024 ] count=40
#	sync
	date
done
