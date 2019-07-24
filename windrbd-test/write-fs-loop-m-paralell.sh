# DRIVE=f
DRIVE=m

do_write() {
i=0
while [ $i -lt 100 ]
do
	i=$[ $i+1 ]
	echo Write File $i
	#cp /dev/urandom /cygdrive/k/data
	dd if=/dev/zero of=/cygdrive/$DRIVE/data$1 bs=1024 count=1024
	sync
#	sleep 1
done
}

do_read() {
i=0
while [ $i -lt 100 ]
do
	i=$[ $i+1 ]
	echo Read File $i
	#cp /dev/urandom /cygdrive/k/data
	dd of=/dev/null if=/cygdrive/$DRIVE/data$1 bs=1024 count=1024
	sync
#	sleep 1
done
}

i=0
while [ $i -lt 50 ]
do
	i=$[ $i+1 ]
	do_write $i &
	do_read $i &
done
