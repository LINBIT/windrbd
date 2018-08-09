res=${RES:-w0}
export LOOP_CNT=${LOOP_CNT:-100}
megs=${REQ_SIZE:-2}
size=${SIZE:-49}
drive=${DRIVE:-'k:'}

drbdadm up $res
drbdadm primary $res
windrbd inject-faults-on-completion $drive 100
./loop.sh 'rw test' 0 ./write-disk-one-meg.sh $drive $[ $size*1024*1024 ] $[ $megs*1024*1024 ] rw
drbdadm down $res
# also fault injection disabled here .. it is per backing device.
