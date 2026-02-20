#ifndef _ASM_ERRNO_H
#define _ASM_ERRNO_H

/* TODO: this should avoid inclusion of the ReactOS crt errno.h */
#define _INC_ERRNO 1

/* Those match now the Linux values. Use errno utility to convert number
 * to symbol (or symbol to number).
 */

#define EINVAL					22
#define EOPNOTSUPP				95
#define ENOMEM					12
#define ENOENT					2
#define EROFS					30
#define	E2BIG					7
#define ETIMEDOUT				110
#define EBUSY					16
#define	EAGAIN					11
#define ENOBUFS					105
#define ENODEV					19
#define EWOULDBLOCK				11
#define EINTR					4
#define ENOSPC					28
#define ECONNRESET				104
#define EIO					5
#define ENOMSG					42
#define EEXIST					17
#define EPERM					1
#define EMSGSIZE				90
#define ESRCH					3
#define ERANGE					34
#define EINPROGRESS				115
#define ECONNREFUSED				111
#define ENETUNREACH				101
#define EHOSTUNREACH				113
#define EBADR					53
#define EADDRINUSE				98
#define	EOVERFLOW				75
#define	ESTALE					11
#define ECONNABORTED				103
#define ENODATA					61
#define ENOTCONN				107
#define EADDRNOTAVAIL				99
#define ENOTSUP					95
#define EACCES					13
#define ENOTUNIQ				76

#define ERESTARTSYS				512
#define EMEDIUMTYPE				513
#define ENOTSUPP				514
#define EHOSTDOWN				515

#define EDESTADDRREQ	89      /* Destination address required */
#define EFAULT		14	/* Bad address */
#define EPROTO		85	/* Protocol error */
#define ENOTRECOVERABLE	131	/* State not recoverable */

#define ENOKEY          126     /* Required key not available */
#define ENOSYS          38      /* Invalid system call number */

#endif
