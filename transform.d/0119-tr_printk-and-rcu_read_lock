#!/usr/bin/perl -pi.bak

sub BEGIN
{
	@ARGV = grep(/drbd_transport\.h/, @ARGV);
	exit unless @ARGV;

	$/ = "";
}

# cocchinelle doesn't work inside macros.

#  #define tr_printk(level, transport, fmt, args...)  ({		\
# -    rcu_read_lock();							\
# +    int rcu_flags;							\
# +    rcu_flags = rcu_read_lock();					\
#      printk(level "drbd %s %s:%s: " fmt,			\
#             (transport)->log_prefix,				\
#             (transport)->class->name,			\
#             rcu_dereference((transport)->net_conf)->name,	\
#             ## args);					\
# -    rcu_read_unlock();						\
# +    rcu_read_unlock(rcu_flags);					\
#      })


/^\s*\#\s*define\s+tr_printk/ and
($_ = <<'EOT');

#define tr_printk(level, transport, fmt, ...)  {                        \
    KIRQL _tr_printk_rcu_flags;                                         \
    _tr_printk_rcu_flags = rcu_read_lock();                             \
    printk(level "drbd %s %s:%s: " fmt,                                 \
           (transport)->log_prefix,                                     \
           (transport)->class->name,                                    \
           rcu_dereference((transport)->net_conf)->name,                \
           __VA_ARGS__);                                                \
    rcu_read_unlock(_tr_printk_rcu_flags);                              \
    }

EOT

