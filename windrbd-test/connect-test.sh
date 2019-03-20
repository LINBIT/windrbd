#!/bin/bash

i=0
while true
do 
	i=$[ $i+1 ]
	echo Up $i
	drbdadm up vamp-4nodes
	echo Wait-connect $i
	drbdadm wait-connect vamp-4nodes
	echo Connected $i
	drbdadm status
	echo Down $i
	drbdadm down vamp-4nodes
done
