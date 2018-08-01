if [ $# -lt 3 ]
then
	echo "Usage: $0 <msg> <sleep-interval> <cmd>"
	exit 1
fi

msg=$1
shift

sleep_interval=$1
shift

loop_cnt=${LOOP_CNT:-1000000}

i=0
while [ $i -lt $loop_cnt ]
do
	i=$[ $i+1 ]
	echo $msg $i
	$*
	sleep $sleep_interval
done
