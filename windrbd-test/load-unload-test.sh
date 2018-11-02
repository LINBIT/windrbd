drbdadm up w0 ; sleep 2 ; drbdadm down all ; sc stop windrbdumhelper ; sc stop windrbdlog ; sc stop windrbd ; sc query windrbd
