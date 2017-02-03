#!/usr/bin/perl -pi.bak


sub BEGIN {
    $/ = "}";
}


# -void connect_timer_fn(unsigned long data)
# -{
# +void connect_timer_fn(PKDPC Dpc, PVOID data, PVOID arg1, PVOID arg2)
# +{
# +    UNREFERENCED_PARAMETER(...)
s( ^ (void \s* \w+_timer_fn ) \( unsigned \s long \s (\w+) \) \s* \{ )
 (                          "$1(PKDPC Dpc, PVOID $2, PVOID arg1, PVOID arg2)" .
                            "{\n" .
                            "    UNREFERENCED_PARAMETER(Dpc);\n" .
                            "    UNREFERENCED_PARAMETER(arg1);\n" .
                            "    UNREFERENCED_PARAMETER(arg2);\n"
 )ex;


# -   resync_timer_fn((unsigned long)peer_device);
# +   resync_timer_fn(NULL, peer_device, 0, 0);
s( ^ ( \s* \w+_timer_fn ) \( \( unsigned \s long\) (\w+) \) )
 (                    "$1(NULL, $2, 0, 0);" )ex;

