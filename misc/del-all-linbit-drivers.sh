# have to adjust -c param ... TODO: this should be
# done by the installer
# for i in $( pnputil -e | grep LINBIT -B 5 | grep oem | cut -c 29-37 ) ; do pnputil -d $i ; done
# something like this:
for i in $( pnputil -e | grep provider.*Linbit -B 1 | grep oem | cut -c 29-37 | tr -d ' ' ) ; do echo pnputil -d $i ; done
