if [ $# -lt 1 ] ; then 
	echo "Usage: $0 <files-to-upload-to-LINBIT-SDS>"
	exit 1
fi

for f in $*
do
	pulp --format none file content upload   --repository LinbitSDSForWindows --file $f --relative-path $f
	pulp --format none file content upload   --repository LinbitSDSForWindows --file $f --relative-path install-linbit-sds-latest.exe
done
