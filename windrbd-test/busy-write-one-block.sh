# secondary:
drbdadm disconnect busy-resync-test
drbdadm invalidate busy-resync-test
# primary
# ./fio-3.27-x64/fio --name=r:\\fio-test --size=1000m --rw=write --direct=1 --thread --runtime=600
# (done my invalidate now)
# primary
./fio-3.27-x64/fio --name=r:\\fio-test --size=4k --rw=write --direct=1 --bs=4k --iodepth=32 --thread --runtime=600 --time_based --numjobs=32
# secondary:
drbdadm connect busy-resync-test
# secondary:
drbdsetup events2
