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
# format is unstable with CygWin
# echo -e 'j\nj\nj\nj\nj\n' | format.com ${DRIVE_LETTER}:
cp /dev/urandom /cygdrive/${DRIVE_LETTER}/data
sync
drbdadm secondary $RES
drbdadm down $RES

