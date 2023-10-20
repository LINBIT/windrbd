i=0

while true
do
	i=$[ $i+1 ]
	echo starting rds resource $i ...
	date
	drbdadm -d up rds_resource
	drbdadm up rds_resource
	sleep 60
done
