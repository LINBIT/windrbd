#!/bin/bash
# this is a very simple cgi-bin script that serves a (DRBD)
# block device for use by a ipxe sanboot over http. To use
# configure apache2 (or any other webserver) for cgi-bin
# and copy this script into the cgi-bin directory.
#
# It supports the range http header. It does not support keep-alive.
# It expects the DRBD minor as parameter 
#
# Sample URL:
# http://example.com/cgi-bin/drbd.cgi?DRBD_MINOR=1

# Making DRBD resource primary in not needed, since reading works
# with DRBD 9 also when Secondary and there are no primaries.

var=${QUERY_STRING%=*}
val=${QUERY_STRING#*=}

if [ $var != 'DRBD_MINOR' ] ; then
	echo 'Required parameter DRBD_MINOR not given' 1>&2
	exit 1
fi
echo $val | grep ^[0-9][0-9]*$ > /dev/null
if [ $? -ne 0 ] ; then
	echo 'DRBD_MINOR value must be numeric' 1>&2
	exit 1
fi

DEVICE=/dev/drbd$val

if [ x"$REQUEST_METHOD" == xHEAD ] ; then
# currently there is a limit somewhere between 8455716864 and 8589934592 bytes
# iPXE will report I/O errors

	TOTAL_LENGTH=`blockdev --getsize64 $DEVICE`

	echo 'Content-type: application/octet-stream'
	echo "Content-length: $TOTAL_LENGTH"
	echo
	exit 0
fi

BLOCKSIZE=512
if [ x"$HTTP_RANGE" == x ] ; then
	TOTAL_LENGTH=`blockdev --getsize64 $DEVICE`

	echo "Warning: No HTTP_RANGE given, sending whole blockdev ($TOTAL_LENGTH)" 1>&2
	FROM=0
	TO=$[ $TOTAL_SIZE - 1 ]
else
	echo "Range is $HTTP_RANGE" 1>&2
	FROM=$[ `echo $HTTP_RANGE | cut -d= -f 2 | cut -d- -f 1` ]
	TO=$[ `echo $HTTP_RANGE | cut -d= -f 2 | cut -d- -f 2` ]
fi
LENGTH=$[ $TO - $FROM + 1 ]

if [ $[ $FROM % $BLOCKSIZE ] -ne 0 ] ; then
	echo "Start offset not multiple of $BLOCKSIZE (is $FROM)" 1>&2
	exit 1
fi
if [ $[ $LENGTH % $BLOCKSIZE ] -ne 0 ] ; then
	echo "Length not multiple of $BLOCKSIZE (is $LENGTH)" 1>&2
	exit 1
fi
FROMBLOCK=$[ $FROM / $BLOCKSIZE ]
BLOCKS=$[ $LENGTH / $BLOCKSIZE ]

echo 'Content-type: application/octet-stream'
echo "Content-length: $LENGTH"
echo

dd if=$DEVICE bs=$BLOCKSIZE skip=$FROMBLOCK count=$BLOCKS status=none
