set -x

RES=w0
DRIVE=/cygdrive/k

drbdadm up $RES
drbdadm down $RES

drbdadm up $RES
drbdadm detach $RES
drbdadm attach $RES
drbdadm down $RES

drbdadm up $RES
drbdadm primary $RES
drbdadm secondary $RES
drbdadm down $RES

drbdadm up $RES
drbdadm primary $RES
cp /dev/urandom $DRIVE/data
drbdadm secondary $RES
drbdadm down $RES

