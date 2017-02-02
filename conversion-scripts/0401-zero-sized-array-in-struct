#!/bin/bash


# We can't change the [0] in drbd_protocol.h because that would change packet size calculation.
# Turned the compiler warning off.


# drbd-headers\linux/drbd_genl.h(90): warning C4200: nonstandard extension used: zero-sized array in struct/union^M
# drbd-headers\linux/drbd_genl.h(90): error C2229: struct 'drbd_cfg_reply' has an illegal zero-sized array^M
#
#   but coccinelle can't do the genlink files...
#
# ERROR-RECOV: end of file while in recovery mode
#   parsing pass2: try again
#   ERROR-RECOV: end of file while in recovery mode
#   parse error
#    = File "converted-sources/drbd-headers/linux/drbd_genl.h", line 99, column 1,  charpos = 3366
#       around = '__u32_field', whole content =     __u32_field(1, DRBD_GENLA_F_MANDATORY,  ctx_volume)
#   badcount: 455

## @@
## identifier id, name, type, flags, member;
## @@
## GENL_struct(id, 1, name,
## 	type(1, flags, member,
## -	0
## +	1
## 	))

# GENL_struct(DRBD_NLA_CFG_REPLY, 1, drbd_cfg_reply,
# 		/* "arbitrary" size strings, nla_policy.len = 0 */
# 	__str_field(1, DRBD_GENLA_F_MANDATORY,	info_text, 0)
# )
perl -pi.bak -e 's/^(\s*__str_field\(.*),\s*0\)\s*$/$1, 1)/;' "$@"
