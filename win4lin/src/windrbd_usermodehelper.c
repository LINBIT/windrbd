#include "drbd_windows.h"
#include "drbd_wrappers.h"
#include "windrbd_ioctl.h"
/* #include "windrbd/windrbd_ioctl.h" */
#include <linux/list.h>

/* In case daemon is not running or a process takes longer than that
 * to terminate, timeout after 1 second. This should not be too long
 * since there are DRBD processes stalled while waiting.
 */

/* This timeout is between call_usermodehelper and some daemon to
 * fetch the request.
 */
#define REQUEST_TIMEOUT_MS 1000

/* This timeout is between some daemon to fetch the request and the
 * daemon returning the requests response (in practice this defines
 * how long a script may run). Since we are now using PowerShell which
 * is just too damn slow we put this to 10 seconds for now.
 */
#define RETURN_TIMEOUT_MS 10000

struct um_request {
	struct list_head list;
	KEVENT request_event;
	KEVENT return_event;
	int retval;
	struct windrbd_usermode_helper helper;
		/* DO NOT put anything after this member, it contains
		 * a variable length data member at its end. */
};

static struct mutex request_mutex;
static LIST_HEAD(um_requests);
static LIST_HEAD(um_requests_running);

static int string_table_to_buffer(char *buf, const char **argv, size_t max_size, size_t *actual_size)
{
	int argc;
	size_t pos;

	argc = 0;
	pos = 0;
	while (*argv != NULL) {
		size_t len;

		len = strlen(*argv)+1;
		if (buf != NULL && pos+len <= max_size)
			strcpy(buf+pos, *argv);

		pos += len;
		argv++;
		argc++;
	}
	if (actual_size != NULL)
		*actual_size = pos;

	return argc;
}

int call_usermodehelper(char *path, char **argv, char **envp, enum umh_wait wait)
{
	static int unique_id;
	struct um_request *new_request;
	size_t path_size, arg_size, env_size, total_size, total_size_of_helper;
	char *buf;
	NTSTATUS status;
	LARGE_INTEGER timeout;
	int ret;
	if (wait != UMH_WAIT_PROC) {
		printk("Only UMH_WAIT_PROC supported for wait (is %d)\n", wait);
		return -EOPNOTSUPP;
	}
	path_size = strlen(path)+1;
	string_table_to_buffer(NULL, argv, 0, &arg_size);
	string_table_to_buffer(NULL, envp, 0, &env_size);

	total_size = sizeof(struct um_request)+path_size+arg_size+env_size;
	total_size_of_helper = sizeof(struct windrbd_usermode_helper)+path_size+arg_size+env_size;

	new_request = kmalloc(total_size, 0, 'DRBD');
	if (new_request == NULL)
		return -ENOMEM;

	KeInitializeEvent(&new_request->request_event, SynchronizationEvent, FALSE);
	KeInitializeEvent(&new_request->return_event, SynchronizationEvent, FALSE);
	new_request->retval = -ETIMEDOUT;
	new_request->helper.id = unique_id++;
	new_request->helper.total_size = total_size_of_helper;
	buf = &new_request->helper.data[0];
	strcpy(buf, path);
	buf+=path_size;
	new_request->helper.argc = string_table_to_buffer(buf, argv, arg_size, NULL);
	buf+=arg_size;
	new_request->helper.envc = string_table_to_buffer(buf, envp, env_size, NULL);

	mutex_lock(&request_mutex);
	list_add(&new_request->list, &um_requests);
	mutex_unlock(&request_mutex);

	timeout.QuadPart = -10*1000*REQUEST_TIMEOUT_MS;

	status = KeWaitForSingleObject(&new_request->request_event, Executive, KernelMode, FALSE, &timeout);

	if (status == STATUS_TIMEOUT) {
		printk("User mode helper request timed out after %d milliseconds, is the user mode helper daemon running?\n", REQUEST_TIMEOUT_MS);
		ret = -ETIMEDOUT;
	} else {
		timeout.QuadPart = -10*1000*RETURN_TIMEOUT_MS;
		status = KeWaitForSingleObject(&new_request->return_event, Executive, KernelMode, FALSE, &timeout);

		if (status == STATUS_TIMEOUT) {
			printk("User mode helper return request timed out after %d milliseconds, is the script running too slow?\n", RETURN_TIMEOUT_MS);
			ret = -ETIMEDOUT;
		} else {
			ret = new_request->retval;
			printk("User mode helper returned %d (exit status is %d)\n", ret, (ret >> 8) & 0xff);
		}
	}

	mutex_lock(&request_mutex);
	list_del(&new_request->list);
	mutex_unlock(&request_mutex);

	kfree(new_request);

	return ret;
}

	/* IOCTL_WINDRBD_ROOT_RECEIVE_USERMODE_HELPER ioctl */

int windrbd_um_get_next_request(void *buf, size_t max_data_size, size_t *actual_data_size)
{
	struct um_request *r;
	int ret = 0;
	size_t bytes_copied = 0;

	mutex_lock(&request_mutex);
	if (!list_empty(&um_requests)) {
		r=list_first_entry(&um_requests, struct um_request, list);

		if (max_data_size >= r->helper.total_size) {
			bytes_copied = r->helper.total_size;
			RtlCopyMemory(buf, &r->helper, bytes_copied);

				/* put on another list, so we do not
				 * return that request later again.
				 */

			list_del(&r->list);
			list_add(&r->list, &um_requests_running);

			KeSetEvent(&r->request_event, 0, FALSE);
		} else {
				/* Userspace only wants to know size */
			if (max_data_size >= sizeof(r->helper)) {
				bytes_copied = sizeof(r->helper);
				RtlCopyMemory(buf, &r->helper, bytes_copied);
			} else {
				ret = -EINVAL;
			}
		}
	} else {
		ret = -EAGAIN;
	}
	mutex_unlock(&request_mutex);

	if (actual_data_size)
		*actual_data_size = bytes_copied;

	return ret;
}

	/* IOCTL_WINDRBD_ROOT_SEND_USERMODE_HELPER_RETURN_VALUE ioctl */

int windrbd_um_return_return_value(void *rv_buf)
{
	struct um_request *r;
	struct windrbd_usermode_helper_return_value *rv = rv_buf;
	int ret = -1;

	mutex_lock(&request_mutex);
	list_for_each_entry(struct um_request, r, &um_requests_running, list) {
		if (rv->id == r->helper.id) {
			r->retval = rv->retval;
			KeSetEvent(&r->return_event, 0, FALSE);
			ret = 0;

			break;
		}
	}
	mutex_unlock(&request_mutex);

	return ret;

}

int windrbd_init_usermode_helper(void)
{
	mutex_init(&request_mutex);

	return 0;
}
