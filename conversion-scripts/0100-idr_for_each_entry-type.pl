#!/usr/bin/perl -pi.bak


our %types;
sub BEGIN {
%types = qw(    peer_device          drbd_peer_device
                device               drbd_device
                r                    drbd_request
                next_resource        drbd_resource
                e                    lc_element
                req                  drbd_request
                path                 drbd_path
                q                    struct queued_twopc
                );
};


# - idr_for_each_entry(&resource->devices, device, vnr)
# + idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
s{
	( \s idr_for_each_entry
		\( [^,]+, )
	((\w+),)
}{
	my $t = $types{$3};
	$t ?  $1 . "struct $t *, $2"  : "$1$2";
}xe;

# - idr_for_each_entry(&resource->devices, device, vnr)
# + idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
s{
	( \s (?: list_for_each_entry ( _continue | _safe | _reverse | _rcu )* 
		| list_next_entry ) 
		\( )
	((\w+),)
}{
	my $t = $types{$4};
	$t ?  $1 . "struct $t, $3" : "$1$3";
}xe;

