# DRIVE=f
DRIVE=k
# DRIVE=h
# DRIVE=c

i=0
while true
do
	i=$[ $i+1 ]
	echo Write File $i
	date
	time (
		dd if=/dev/zero of=/cygdrive/$DRIVE/data bs=4096 count=10000
		sync
	)
	sleep 1
done
