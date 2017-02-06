#!/usr/bin/perl -pi.bak

sub BEGIN
{
	@ARGV = grep(/drbd_int\.h/, @ARGV);
	exit unless @ARGV;
}

s{i_size_read\((\w+)\-\>bd_inode\)}
 {(wdrbd_get_capacity($1) << 9)};
