#!/usr/bin/perl -pi.bak
# vim: set et :


our %types;
sub BEGIN {
%types = qw(
                e                    lc_element
                device               drbd_device
                debug_lock           kref_debug_info
                other_device         drbd_device
                connection           drbd_connection
                listener             drbd_listener    
                r                    drbd_request
                req                  drbd_request
                req2                 drbd_request
                tmp                  drbd_request
                next_resource        drbd_resource
                resource             drbd_resource
                path                 drbd_path
                peer_device          drbd_peer_device
                peer_req             drbd_peer_request
                pr                   drbd_peer_request
                rs_req               drbd_peer_request
                q                    queued_twopc
                q2                   queued_twopc
                twopc_parent         drbd_connection
                transport_class      drbd_transport_class
                tc                   drbd_transport_class
                );
};


# - idr_for_each_entry(&resource->devices, device, vnr)
# + idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
# But only at line start, not after #define.
s{ ^
	( \s+ idr_for_each_entry \( )
	( [^,]+ ) , \s*
	(\w+), \s*
	(\w+)
	\)
}{
	my $t = $types{$3};
	$1 . "struct $t *, $2, $3, $4)"
}xe;


# Only at line start, not after #define.
s{ ^
	( \s+ (?: h? list_for_each_entry ( _continue | _safe | _reverse | _rcu )*
		| \w+\s*=\s*list_prepare_entry    # variable = ...
		| list_next_entry )
		\( )
	((\w+),)
}{
	my $t = $types{$4};
	$t ?  $1 . "struct $t, $3" : "$1$3";
}xe;

