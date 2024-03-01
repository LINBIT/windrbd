#ifndef _UAPI_TIME_H
#define _UAPI_TIME_H

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};

#endif
