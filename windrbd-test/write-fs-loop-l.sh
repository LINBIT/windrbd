# DRIVE=f
DRIVE=l
i=0
while true
do
	i=$[ $i+1 ]
	echo Write File $i
	#cp /dev/urandom /cygdrive/k/data
	cp /dev/zero /cygdrive/$DRIVE/data
	sync
#	sleep 1
done
