#!/usr/bin/perl -pi.bak

sub BEGIN
{
	@ARGV = grep(/drbd_int\.h/, @ARGV);
	exit unless @ARGV;
}

s{kobject_uevent\(disk_to_kobj\(device\-\>vdisk\), KOBJ_CHANGE\);}
 {/* kobject_uevent(...) call removed by transformation 0121 */};
