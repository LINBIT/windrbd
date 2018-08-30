# this should not BSOD
# it is normal that the test shows I/O errors since we fault inject here

res=${RES:-w0}
export LOOP_CNT=${LOOP_CNT:-3}
megs=${REQ_SIZE:-2}
size=${SIZE:-49}
drive=${DRIVE:-'k:'}

drbdadm down $res
drbdadm up $res
drbdadm primary $res --force
windrbd inject-faults 100 backing-completion $drive
loop.sh 'rw test' 0 write-disk-one-meg.sh $drive $[ $size*1024*1024 ] $[ $megs*1024*1024 ] rw
drbdadm down $res
# also fault injection disabled here .. it is per backing device which does not exist any more.
