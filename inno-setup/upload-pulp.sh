if [ $# -lt 1 ] ; then 
	echo "Usage: $0 <files-to-upload-to-WinDRBD>"
	exit 1
fi

for f in $*
do
	pulp file content upload   --repository WinDRBD2   --file $f --relative-path $f
done
