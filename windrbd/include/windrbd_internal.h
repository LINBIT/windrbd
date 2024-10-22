/*
        Copyright(C) 2017-2018, Johannes Thoma <johannes@johannesthoma.com>
        Copyright(C) 2017-2018, LINBIT HA-Solutions GmbH  <office@linbit.com>
	Copyright(C) 2007-2016, ManTechnology Co., LTD.
	Copyright(C) 2007-2016, wdrbd@mantech.co.kr

	Windows DRBD is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	Windows DRBD is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Windows DRBD; see the file COPYING. If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _WINDRBD_INT_H
#define _WINDRBD_INT_H

#include <linux/types.h>
#include <linux/blk_types.h>
#include <windrbd_config.h>
#include <windrbd/windrbd_ioctl.h>
#include <windrbd.h>

extern NTSTATUS mvolAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject);

typedef struct _ROOT_EXTENSION
{
	int dummy;
} ROOT_EXTENSION, *PROOT_EXTENSION;

typedef struct _BUS_EXTENSION
{
	struct _DEVICE_OBJECT *lower_device;
} BUS_EXTENSION, *PBUS_EXTENSION;

extern PDEVICE_OBJECT		mvolRootDeviceObject;
extern PDEVICE_OBJECT		user_device_object;
extern PDRIVER_OBJECT		mvolDriverObject;
extern PDEVICE_OBJECT		drbd_bus_device;
extern PDEVICE_OBJECT		drbd_physical_bus_device;

// extern int drbd_init(void);

extern void init_windrbd(void);

/* see printk-to-syslog.c */
extern int debug_printks_enabled;
extern int initialize_syslog_printk(void);
extern void shutdown_syslog_printk(void);
extern void set_syslog_ip(const char *ip);

#define cond_printk(args...) \
	if (debug_printks_enabled) \
		_printk(__FUNCTION__, args)

/* Windows event log. printk's at level <= level set by set_event_log_threshold
 * will appear in Windows event log.
 */
void init_event_log(void);
void set_event_log_threshold(int level);

extern void init_free_bios(void);
extern void shutdown_free_bios(void);

extern int init_registry(PUNICODE_STRING registry_path);

/* See windrbd_device */
extern void windrbd_set_major_functions(struct _DRIVER_OBJECT *obj);

/* See windrbd_netlink */
void windrbd_init_netlink(void);
void windrbd_shutdown_netlink(void);

/* See windrbd_winsocket */
NTSTATUS windrbd_init_wsk(void);
void windrbd_shutdown_wsk(void);

/* See windrbd_usermode_helper */
int windrbd_init_usermode_helper(void);

/* Run internal unit tests. */
void windrbd_run_tests(void);
void windrbd_shutdown_tests(void);

/* See windrbd_bootdevice.c */
int create_drbd_resource_from_url(const char *url);
void windrbd_init_boot_device(void);

/* TODO: We put this here, since this should be included by most WinDRBD
 * C source files. One day we probably find a better way.
 */
// int __cdecl _snwprintf(wchar_t *_Dest,size_t _Count,const wchar_t *_Format,...);

void windrbd_bus_is_ready(void);
int windrbd_wait_for_bus_object(void);

/* In some Windows functions this is still used ... */
#define DRBD_TAG 0x44425144
#define FREE_TAG 0x45455146

/* util.c: */
NTSTATUS get_registry_int(wchar_t *key, int *val_p, int the_default);
NTSTATUS get_registry_long_long(wchar_t *key, unsigned long long *val_p, unsigned long long the_default);

/* windrbd_netlink.c: */
int windrbd_process_netlink_packet(void *msg, size_t msg_size);
size_t windrbd_receive_netlink_packets(void *vbuf, size_t remaining_size, u32 portid);
bool windrbd_are_there_netlink_packets(u32 portid);	/* non-blocking peek at netlink packets. Does not consume them. */
int windrbd_join_multicast_group(u32 portid, const char *name, struct _FILE_OBJECT *f);
int windrbd_delete_multicast_groups_for_file(struct _FILE_OBJECT *f);

/* printk_to_syslog.c: */

struct in_addr;
int my_inet_aton(const char *cp, struct in_addr *inp);
char *my_inet_ntoa(struct in_addr *addr);

int windrbd_create_windows_device_for_minor(int minor);

/* These are needed by windrbd_device.c: */
int windrbd_inject_faults(int after, enum fault_injection_location where, struct block_device *windrbd_bdev);
int windrbd_um_get_next_request(void *buf, size_t max_data_size, size_t *actual_data_size);
int windrbd_um_return_return_value(void *rv_buf);

/* windrbd_test.c: */
void test_main(const char *arg);

int lock_interface(const char *config_key_param);
int windrbd_is_locked(void);
int set_driver_locked_state(int state);


/* drbd_main.c: TODO: into some another header */
struct drbd_device;
// extern int try_to_promote(struct drbd_device *device, long timeout, bool ndelay);

extern ULONG_PTR crc32(const char *s, size_t len);

/* Implemented in windrbd_test: base works now from 2 to 36 */
/* TODO: replace these with Linux functions. */
unsigned long long my_strtoull(const char *nptr, const char ** endptr, int base);
int my_atoi(const char *c);

/* Thread functions */

NTSTATUS windrbd_create_windows_thread(void (*threadfn)(void*), void *data, void **thread_object_p);
NTSTATUS windrbd_cleanup_windows_thread(void *thread_object);

void init_windrbd_threads(void);

	/* Currently called by reply_reaper, see netlink code */
void windrbd_reap_threads(void);

	/* This waits forever, only use this on driver unload */
void windrbd_reap_all_threads(void);

struct task_struct* windrbd_find_thread(PKTHREAD id);

        /* Use this to create a task_struct for a Windows thread
         * This is needed so we can call wait_event_XXX functions
         * within those threads.
         */

struct task_struct *make_me_a_windrbd_thread(const char *name, ...);

        /* Call this when a thread returns to the calling Windows
         * kernel function.
         */

void return_to_windows(struct task_struct *t);

/* Non-zero if thread is created via the Linux emulation layer (this
 * file).
 */

bool is_windrbd_thread(struct task_struct *t);

/* Set realtime priority. Used for asender */

void windrbd_set_realtime_priority(struct task_struct *t);

/* Become super user */
void sudo(void);

void *OpenSerialPort(void);
void WriteSerial(char *buf, size_t length);
void WriteStringSerial(char *buf);
void PrintfSerial(char *fmt, ...);

#endif
