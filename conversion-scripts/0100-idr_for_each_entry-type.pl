#!/usr/bin/perl -pi.bak


our %types;
sub BEGIN {
%types = qw(   	peer_device drbd_peer_device
				r			drbd_request
				e			lc_element
				req			drbd_request
				drbd_path	drbd_path
				);
};

s{ 
	( \s (?: list_for_each_entry ( _continue | _safe | _reverse | _rcu )* 
		| list_next_entry ) 
		\( )
	((\w+),) 
}{
	my $t = $types{$4};
	$t ?  $1 . "struct $t, " . $3 : "$1$3";
}xe;

