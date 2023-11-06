if [ $# -lt 2 ]
then
    echo "Usage: $0 <filename> <ip> <list-of-ssh-ports...>"
    echo "Use this if VMs are accessible via port forwarding"
    echo "Port forwarding can be configured with:"
    echo "ssh -L 0.0.0.0:2222:192.168.122.234:22 Administrator@192.168.122.234 \"tail -f /dev/null\""
    echo
    echo "For example:"
    echo "$0 install-windrbd-1.1.3.exe 10.43.224.38 2234 2235"
    exit 1
fi

FILE=$1
shift
IP=$1
shift

PROG=$( basename $FILE )

parallel scp -P {} ./$FILE Administrator@$IP: ::: $*
parallel ssh -p {} Administrator@$IP "./$PROG /verysilent /norestart" ::: $*
parallel ssh -p {} Administrator@$IP "drbdadm --version" ::: $*
