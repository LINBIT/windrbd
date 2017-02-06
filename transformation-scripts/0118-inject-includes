#!/usr/bin/perl -i.bak

sub BEGIN
{
	@ARGV = grep(/genl_magic_struct\.h/, @ARGV);
	exit unless @ARGV;
}

# when encountering linux/genetlink.h, add drbd_wingenl.h.
# Doesn't work earlier, must not be added later.
while (<>) {
	print;

	print "#include <drbd_wingenl.h>\n" if m(include.*linux/genetlink.h);
}
