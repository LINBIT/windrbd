i=0

while true
do
	i=$[ $i+1 ]
	echo "Resize $i ..."
	diskpart /s resize-backing-device.diskpart
	drbdadm resize reattach2
	diskpart /s resize-windrbd-device.diskpart

	df /cygdrive/g
# and check if it still can be mounted:
	drbdadm secondary reattach2
	drbdadm primary reattach2

	cat /cygdrive/g/data

	sleep 5 
done
