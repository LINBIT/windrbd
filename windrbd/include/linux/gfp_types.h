#ifndef GFP_TYPES_H
#define GFP_TYPES_H

/* TODO: review values. */

#define __GFP_HIGHMEM           (0x02u)
#define __GFP_ZERO              (0x8000u) 
#define __GFP_WAIT              (0x10u) 
#define __GFP_NOWARN            (0x200u)
#define __GFP_RECLAIM           (0x400u)
#define __GFP_NORETRY		(0x10000u)

#define GFP_HIGHUSER            (7)

#define GFP_KERNEL              1
#define GFP_ATOMIC              2
#define GFP_NOIO				(__GFP_WAIT)
#define GFP_NOWAIT	            0

#endif
