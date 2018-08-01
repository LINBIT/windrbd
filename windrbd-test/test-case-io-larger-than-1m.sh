res=${RES:-w0}
export LOOP_CNT=${LOOP_CNT:-100}

# TODO: here enable fault injection via a to-be-done ioctl interface

drbdadm up $res
drbdadm primary $res
./loop.sh 'rw test' 0 ./write-disk-one-meg.sh k: $[ 49*1024*1024 ] $[ 2*1024*1024 ] rw
drbdadm down $res

# TODO: here disable fault injection again
