if [ $# -lt 2 ]
then
    echo "Usage: $0 <filename> <list-of-hosts...>"
    echo "For example:"
    echo "$0 install-windrbd-1.1.3.exe 10.43.224.37 10.43.224.50 10.43.224.69 10.43.224.72 10.43.224.73 10.43.224.74 10.43.224.75"
    exit 1
fi

FILE=$1
shift

parallel scp ./$FILE Administrator@{}: ::: $*
parallel ssh Administrator@{} "./$FILE /verysilent /norestart" ::: $*
parallel ssh Administrator@{} "drbdadm --version" ::: $*
