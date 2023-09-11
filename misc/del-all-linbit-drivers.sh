for i in $( pnputil -e | grep LINBIT -B 5 | grep oem | cut -c 29-36 ) ; do pnputil -d $i ; done
