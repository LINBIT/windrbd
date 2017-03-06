#!/usr/bin/perl -pi.bak

# -#define GENL_op_init(args...)	args
# +#define GENL_op_init(...)	__VA_ARGS__


s{ ^ ( \s* \#define \s+ \w+ ) \( (\w+) \.\.\. \) \s+ \2 $}
 { "$1(...) __VA_ARGS__" }xeg;


# for the transport layer:

# define tr_printk(level, transport, fmt, args...)  ({		\
#    ...
#	       ## args);					\
#	rcu_read_unlock();					\
#	})
sub BEGIN {
	# go through the file per paragraph
	$/ = "";
	# therefore the "g" modifier on the RE above.
}

if (s{ ^ ( \#define \s+ \w+ \( .*? ) (\w+) \.\.\. \)}
	{ "$1...)" }xmesg) {
	my $varname = $2;
	s{ \b $varname \b }{__VA_ARGS__}gmx;
}

