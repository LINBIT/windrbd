#!/usr/bin/perl -pi.bak
# vim: set et sw=4 ts=4 :


# substitute:
#   unsigned long           ULONG_PTR
#   long                    LONG_PTR
# but not
#   unsigned long long bd_size;
#   long long

# example results:
#   static __inline ULONG_PTR
#       ____bm_op(struct drbd_device
#   ULONG_PTR word;
#   ULONG_PTR total = 0;
#   ULONG_PTR _drbd_bm_total_weight(struct drbd_device *device, int bitmap_index)
#   void drbd_bm_mark_range_for_writeout(struct drbd_device *device, ULONG_PTR start, ULONG_PTR end)
#   int drbd_bm_test_bit(struct drbd_peer_device *peer_device, const ULONG_PTR bitnr)
#   ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);

#   printf("# md_offset %llu\n", (long long unsigned)cfg->md_offset);

#   volatile const unsigned long *addr = &page_private(page);                                           |drbd_bitmap.c(889): error C2059: syntax error: 'else'^M                                                

s{ (?<prefix>
        (^ \s* | [,(]\s* )
        ( extern \s+ | const \s+ | volatile \s+ )*
    ) # end of prefix

    (?<to_remove>
        (?<u> unsigned \s+)?    long
    ) # end of to_remove

    (?<rest>
        \s*
        # NOT "long"
        (?! long )
        # BUT must be word-characters or a stop sign.
        # else "\s+ (?! long" might match "  long" by "\s+" only taking the first space
        [\w)*]
    )
}{
    $+{prefix} . ($+{u} ? "U" : "") .  "LONG_PTR" . $+{rest};
}xge;

# 1UL -> ((ULONG_PTR)1)
# 1ULL -> ((ULONG_PTR)1)
s{((?:0x)?[0-9]+)ULL?}
 {((ULONG_PTR)$1)}g;

# test line:
# :T cp drbd/drbd/drbd_receiver.c converted-sources/drbd/ ; conversion-scripts/0200-types.sh converted-sources/drbd/drbd_receiver.c ; diff -u drbd/drbd/drbd_receiver.c converted-sources/drbd/drbd_receiver.c \| colordiff

