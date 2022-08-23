if [ $# -lt 2 ]
then
    echo "Usage: $0 <filename> <list-of-hosts...>"
    echo "For example:"
    echo "$0 install-linstor-server-1.18.2-97-216edb5e6.exe 10.43.224.35 10.43.224.45 10.43.224.48 10.43.224.49 10.43.224.32"
    exit 1
fi

FILE=$1
shift

parallel scp ./$FILE Administrator@{}: ::: $*
parallel ssh Administrator@{} "./$FILE /verysilent /norestart" ::: $*
parallel ssh Administrator@{} "drbdadm --version" ::: $*
