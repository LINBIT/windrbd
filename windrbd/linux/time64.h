#ifndef __TIME64_H__
#define __TIME64_H__

/* Parameters used to convert the timespec values: */
#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

/* Located here for timespec[64]_valid_strict */
#define TIME64_MAX                      ((s64)~((u64)1 << 63))
#define KTIME_MAX                       ((s64)~((u64)1 << 63))
#define KTIME_SEC_MAX                   (KTIME_MAX / NSEC_PER_SEC)

#endif
