res=${RES:-w0}
export LOOP_CNT=${LOOP_CNT:-100}
megs=${REQ_SIZE:-2}
size=${SIZE:-49}

# TODO: here enable fault injection via a to-be-done ioctl interface

drbdadm up $res
drbdadm primary $res
./loop.sh 'rw test' 0 ./write-disk-one-meg.sh k: $[ $size*1024*1024 ] $[ $megs*1024*1024 ] rw
drbdadm down $res

# TODO: here disable fault injection again
