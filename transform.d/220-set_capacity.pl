#!/usr/bin/perl -pi.bak

sub BEGIN
{
	@ARGV = grep(/drbd_int\.h/, @ARGV);
	exit unless @ARGV;
}
#\-\>vdisk\,(\w+)size\)}
s{set_capacity\(device\-\>vdisk, size\)}
 {if (device && device->this_bdev && device->this_bdev)
\tdevice->this_bdev->d_size = size << 9};
# windows as diskless client


s{\tdevice\-\>this_bdev\-\>bd_inode\-\>i_size = \(loff_t\)size \<\< 9;}{};
