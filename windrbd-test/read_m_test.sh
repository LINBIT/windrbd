#!/bin/bash

i=0
while true
do
	i=$[ $i+1 ]
	echo "Read 1M $i"
	./windrbd-test --gtest_filter=windrbd.do_write_read_whole_disk_by_1meg_requests --mode=r --drive=M: --force --expected-size=$[ 45*1024*1024 ]
done

