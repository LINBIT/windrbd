set -x

RES=w0
DRIVE_LETTER=k

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
echo -e 'j\nj\nj\nj\nj\n' | format.com ${DRIVE_LETTER}:
sleep 5
cp /dev/urandom /cygdrive/${DRIVE_LETTER}/data
drbdadm secondary $RES
drbdadm down $RES

