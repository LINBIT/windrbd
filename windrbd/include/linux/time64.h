#ifndef __TIME64_H__
#define __TIME64_H__

#include <linux/types.h>
#include <uapi/linux/time.h>

typedef __s64 time64_t;
typedef __u64 timeu64_t;

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

struct timespec64 {
	time64_t	tv_sec;			/* seconds */
	LONG_PTR		tv_nsec;		/* nanoseconds */
};

/**
 * ns_to_timespec64 - Convert nanoseconds to timespec64
 * @nsec:	the nanoseconds value to be converted
 *
 * Returns the timespec64 representation of the nsec parameter.
 */
extern struct timespec64 ns_to_timespec64(s64 nsec);

#endif
