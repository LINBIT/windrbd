#!/usr/bin/perl -pi.bak

sub BEGIN {
	$/ = ';';
	$counter=0;
}

# - b = kzalloc(sizeof(struct drbd_bitmap), GFP_KERNEL);
# + b = kzalloc(sizeof(struct drbd_bitmap), GFP_KERNEL, '11DW');


s{ (?<call> \b (?: kzalloc | kmalloc | bio_alloc | mempool_create_page_pool |  mempool_create_slab_pool) \( )
	(?<arg1> [^,]+  ) ,
	(?<arg2> [^,)]+ ) \)
}{
	my $id = sprintf("'%02XWD'", $counter++);
	die "TOO BIG" if $counter > 0xff;

	"$+{call}$+{arg1},$+{arg2}, $id)"
}ex;

s{ (?<call> \b kcalloc\( )
	(?<arg1> [^,]+  ) ,
	(?<arg2> [^,]+  ) ,
	(?<arg3> [^,)]+ ) \)
}{
	my $id = sprintf("'%02XWD'", $counter++);
	die "TOO BIG" if $counter > 0xff;

	"$+{call}$+{arg1},$+{arg2},$+{arg3}, $id)"
}ex;

s{ (?<call> \b kmem_cache_create\( )
	(?<arg1> [^,]+  ) ,
	(?<arg2> [^,]+  ) ,
	(?<arg3> [^,]+  ) ,
	(?<arg4> [^,]+  ) ,
	(?<arg5> [^,)]+ ) \)
}{
	my $id = sprintf("'%02XWD'", $counter++);
	die "TOO BIG" if $counter > 0xff;

	"$+{call}$+{arg1},$+{arg2},$+{arg3},$+{arg4},$+{arg5}, $id)"
}ex;

s{ (?<call> = \s* \b bio_alloc_drbd \( )
	(?<arg> [^)]+  ) \)
}{
	my $id = sprintf("'%02XWD'", $counter++);
	die "TOO BIG" if $counter > 0xff;

	"$+{call}$+{arg}, $id)"
}ex;


