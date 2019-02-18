#!/bin/bash

i=0
while true
do
	i=$[ $i+1 ]
	echo Write File $i
	cp /dev/zero /home/johannes/Linbit/tmp/mnt/data
	sync
done
