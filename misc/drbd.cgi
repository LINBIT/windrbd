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

# TODO: ipxe seems not to support parameters (the thing after the ?)
# TODO: make keepalive work. It is still slow (about 30 seconds for Windows
# boot CD) good for now but can be better.
# TODO: use drbd resources
# TODO: make drbd resource primary
# TODO: eventually make it secondary again (auto-demote?)

echo 'Content-type: application/octet-stream'
echo

if [ x"$HTTP_RANGE" == x ] ; then
	echo "No HTTP_RANGE given" 1>&2
	exit 1
fi
# if [ x"$DRBD_MINOR" == x ] ; then
# 	echo "No DRBD_MINOR given" 1>&2
# 	exit 1
# fi

BLOCKSIZE=512
FROM=`echo $HTTP_RANGE | cut -d= -f 2 | cut -d- -f 1`
TO=`echo $HTTP_RANGE | cut -d= -f 2 | cut -d- -f 2`
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

# TODO: make DRBD resource primary.

# DEVICE=/dev/drbd${DRBD_MINOR}
DEVICE=/dev/sdd3

# echo "FROM: $FROM TO: $TO" > /tmp/range-$$
dd if=$DEVICE bs=$BLOCKSIZE skip=$FROMBLOCK count=$BLOCKS status=none
