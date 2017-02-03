#!/usr/bin/perl -pi.bak


our %types;
sub BEGIN {
%types = qw(
                e                    lc_element
                device               drbd_device
                r                    drbd_request
                req                  drbd_request
                req2                 drbd_request
                next_resource        drbd_resource
                path                 drbd_path
                peer_device          drbd_peer_device
                peer_req             drbd_peer_request
                q                    queued_twopc
                );
};


# - idr_for_each_entry(&resource->devices, device, vnr)
# + idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
s{
	( \s idr_for_each_entry \( )
	( [^,]+ ) , \s*
	(\w+), \s*
	(\w+)
	\)
}{
	my $t = $types{$3};
	$1 . "struct $t *, $2, $3, $4)"
}xe;


s{
	( \s (?: list_for_each_entry ( _continue | _safe | _reverse | _rcu )*
		| list_next_entry )
		\( )
	((\w+),)
}{
	my $t = $types{$4};
	$t ?  $1 . "struct $t, $3" : "$1$3";
}xe;

