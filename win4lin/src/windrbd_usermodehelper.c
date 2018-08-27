#include "drbd_windows.h"
#include "windrbd_ioctl.h"
#include <linux/list.h>

struct um_request {
	struct list_head list;
	KEVENT request_returned;
	int retval;
	struct windrbd_usermode_helper helper;
		/* DO NOT put anything after this member, it contains
		 * a variable length data member at its end. */
};

static struct mutex request_mutex;
static LIST_HEAD(um_requests);

int call_usermodehelper(char *path, char **argv, char **envp, enum umh_wait wait)
{
	static int unique_id;

	/* Build um_request and add to list. also generate id */

	/* Wait with timeout on return value */

	/* If timeout, drop the request and return errno. */

	/* Else return retval */
	return -EOPNOTSUPP;
}

	/* IOCTL_WINDRBD_ROOT_RECEIVE_USERMODE_HELPER ioctl */

struct windrbd_usermode_helper *windrbd_get_next_request(size_t max_data_size, size_t *actual_data_size)
{
	/* if request on list, return that request, else return NULL */

	/* check total size of request, if buffer too small return size needed
	 * in actual_data_size.
	 */

	/* user space has to busy poll (else we cannot terminate daemon
	 * with Ctrl-C) */

	return NULL;
}

	/* IOCTL_WINDRBD_ROOT_SEND_USERMODE_HELPER_RETURN_VALUE ioctl */

int windrbd_return_return_value(struct windrbd_usermode_helper_return_value *rv)
{
	/* find request on list */

	/* if found signal request_returned and put retval into request */

	/* else return error. In most cases because call_usermodehelper
	 * already timed out
	 */

	return -1;
}
