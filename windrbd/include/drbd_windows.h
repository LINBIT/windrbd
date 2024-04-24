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

#pragma warning (disable : 4100 4146 4221 4457 4456 4459)
#pragma warning (disable : 4005 4018 4101 4115 4121 4127 4131 4152 4189 4200 4201 4204 4212 4218 4242 4244 4245 4267 4307 4389 4702 4706)
/* Code analysis throws this warnings: */
#pragma warning (disable : 26451 28719 6011 6385 6386 26453 33010 6001 28182)
/* Additional warnings in Linux compat layer to silence: */
#pragma warning (disable : 28169 28175 28167)
/* Enable all warnings throws lots of those warnings: */
#pragma warning(disable: 4061 4062 4255 4388 4668 4820 5032  4711 5045)

#ifndef DRBD_WINDOWS_H
#define DRBD_WINDOWS_H

/* Comment that out for production releases. It maps kmem caches to kmalloc
   debug code so we can see who allocated memory.
 */
/* #define KMEM_CACHE_DEBUG 1 */

	/* TODO: we probably want to turn those off: */
/* Enable this (and recompile all) to enable bio reference debugging */
#define BIO_REF_DEBUG 1

/* Enable this (and recompile all) to enable bio allocation debugging */
#define BIO_ALLOC_DEBUG 1

/* Enable this (and recompile all) to enable kref debug tracing */
// #define KREF_DEBUG 1

#define __func_	__FUNCTION__
#define __func__ __FUNCTION__
#define __bitwise__

#define __noop do { }  while (0)

// #include "win2003compat.h"

// #include <winnt.h>
#include <ntdef.h>
#include <ntddk.h>
/* #include <ntifs.h> does not work */
#include <ntstrsafe.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/drbd_endian.h>
#include "linux/types.h"
// #include "generic_compat_stuff.h"
#include "windrbd/windrbd_ioctl.h"

#include "disp.h"
#include <linux/mempool.h>
#include <ntdddisk.h>
#include <linux/bitops.h>

#include <linux/mutex.h>	/* for struct mutex */
#include <linux/spinlock.h>
#include <linux/rwlock.h>

#include "tiktok.h"
#include <ctype.h>

#include <linux/part_stat.h>

void init_windrbd(void);
void msleep(int ms);

struct drbd_transport;
enum drbd_stream;
enum update_sync_bits_mode;

enum
{
	KERN_EMERG_NUM = 0,
	KERN_ALERT_NUM,
	KERN_CRIT_NUM,
	KERN_ERR_NUM,
	KERN_WARNING_NUM,
	KERN_NOTICE_NUM,
	KERN_INFO_NUM,
	KERN_DEBUG_NUM
};

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

// from bio.h
#define BIO_RW					    0       /* Must match RW in req flags (blkdev.h) */
#define BIO_RW_AHEAD				1       /* Must match FAILFAST in req flags */
#define BIO_RW_BARRIER				2
#define BIO_RW_SYNCIO				3
#define BIO_RW_UNPLUG				4
#define BIO_RW_META				    5
#define BIO_RW_DISCARD				6
#define BIO_RW_FAILFAST_DEV			7
#define BIO_RW_FAILFAST_TRANSPORT	8
#define BIO_RW_FAILFAST_DRIVER		9
#define BIO_RW_NOIDLE				10

#define KBUILD_MODNAME      __FILE__

// from notify.h
#define NOTIFY_DONE				    0x0000          /* Don't care */
#define NOTIFY_OK				    0x0001          /* Suits me */
#define NOTIFY_STOP_MASK			0x8000          /* Don't call further */
#define NOTIFY_BAD				    (NOTIFY_STOP_MASK|0x0002)


#define MAX_ERRNO				4095
#define IS_ERR_VALUE(_x)		((_x) >= (ULONG_PTR) -MAX_ERRNO)

// for drbd_actlog.c
// #define __attribute__(packed)
// #define __attribute(packed)
#ifdef LONG_MAX
#undef LONG_MAX
#endif
#define SENDER_SCHEDULE_TIMEOUT	5 * HZ
#define HZ 1000

/* https://msdn.microsoft.com/en-us/library/64ez38eh.aspx */
#pragma intrinsic(_ReturnAddress)
#define _RET_IP_				((void*)_ReturnAddress())


#define likely(_X)				(_X)
#define unlikely(_X)			(_X)

#define PAGE_KERNEL				1
#define	BIO_UPTODATE			1

#define U32_MAX		((u32)~0U)
#define S32_MAX		((s32)(U32_MAX>>1))

enum km_type {
	KM_BOUNCE_READ,
	KM_SKB_SUNRPC_DATA,
	KM_SKB_DATA_SOFTIRQ,
	KM_USER0,
	KM_USER1,
	KM_BIO_SRC_IRQ,
	KM_BIO_DST_IRQ,
	KM_PTE0,
	KM_PTE1,
	KM_IRQ0,
	KM_IRQ1,
	KM_SOFTIRQ0,
	KM_SOFTIRQ1,
	KM_L1_CACHE,
	KM_L2_CACHE,
	KM_KDB,
	KM_TYPE_NR
};

#define MAX_TEXT_BUF                256

#define MAX_SPLIT_BLOCK_SZ			(1 << 20)

#define FLTR_COMPONENT              DPFLTR_DEFAULT_ID
//#define FLTR_COMPONENT              DPFLTR_IHVDRIVER_ID

struct drbd_device;
void windrbd_device_error(struct drbd_device *device, const char ** err_str_out, const char *fmt, ...);

#define ARRAY_SIZE(_x)				(sizeof(_x) / sizeof((_x)[0]))


#define ALIGN(_x,_a)				(((_x) + (_a)-1) & ~((_a)-1))


static inline unsigned int refcount_read(const refcount_t *r)
{
	return atomic_read(&r->refs);
}

static inline void refcount_set(refcount_t *r, int val)
{
	atomic_set(&r->refs, val);
}

static inline bool refcount_dec_and_test(refcount_t *r)
{
        return atomic_dec_and_test(&r->refs);
}



struct block_device;
struct gendisk;
struct bio;

extern sector_t windrbd_get_capacity(struct block_device *bdev);

struct bio;

void init_free_bios(void);
void shutdown_free_bios(void);

	/* To be called at the beginning of conn_disconnect, else
	 * BSOD.
	 */
extern int wait_for_bios_to_complete(struct block_device *bdev);

/* Attention: The backward comp version of this macro accesses bio from
   calling namespace */
#define bio_iter_last(BVEC, ITER) ((ITER) == bio->bi_vcnt - 1)

// DRBD_DOC: not support, it is always newest updated block for windows.
/* TODO: Sure? */
#define bio_flagged(bio, flag)  (1) 
// #define bio_flagged(bio, flag)  ((bio)->bi_flags & (1 << (flag))) 

#define NUMA_NO_NODE 0
struct queue_limits;

extern void blk_queue_segment_boundary(struct request_queue *, unsigned long);
extern int blk_stack_limits(struct queue_limits *t, struct queue_limits *b,
			    sector_t offset);
extern void blk_queue_update_readahead(struct request_queue *q);

static inline void queue_flag_set(unsigned int flag, struct request_queue *q)
{
	if (((int) flag) >= 0)
		__set_bit(flag, &q->queue_flags);
}

static inline void queue_flag_clear(unsigned int flag, struct request_queue *q)
{
	if (((int) flag) >= 0)
		__clear_bit(flag, &q->queue_flags);
}

struct lru_cache;
extern struct lc_element *lc_element_by_index(struct lru_cache *lc, unsigned i);
extern unsigned int lc_index_of(struct lru_cache *lc, struct lc_element *e);

#include <wsk.h>	/* for struct sockaddr_storage */
#include <drbd_transport.h>

extern void __free_page(struct page *page);
extern struct page *alloc_page(int flag);
struct page *alloc_page_of_size(int flag, size_t size);

struct scatterlist {
	struct page *page;
	unsigned int offset;
	unsigned int length;
};

#define BUG()   printk("BUG: failure\n")

#define BUG_ON(_condition)	\
    do {	\
        if(_condition) { \
            printk("BUG: failure\n"); \
        }\
    } while (0)

static inline void assert_spin_locked(spinlock_t *lock)
{
    /* KeTestSpinLock returns FALSE if the spin lock is currently being held.
     * Otherwise, it returns TRUE. */
    BUG_ON(KeTestSpinLock(&lock->spinLock));
}



extern void kobject_put(struct kobject *kobj);
extern void kobject_get(struct kobject *kobj);
extern void kobject_del(struct kobject *kobj);
static inline void * __get_free_page(int flags)
{
    return kzalloc(4096, flags, 'FPWD');
}

	/* TODO: this is a bad name */
static inline void free_page(void *addr)
{
	kfree(addr);
}

struct crypto_tfm;
extern void *crypto_alloc_tfm(char *name, u32 mask);
extern unsigned int crypto_tfm_alg_digestsize(struct crypto_tfm *tfm);
extern int generic_make_request(struct bio *bio); // return value is changed for error handling 2015.12.08(DW-649)

extern void * ERR_PTR(LONG_PTR error);
extern LONG_PTR PTR_ERR(const void *ptr);
extern LONG_PTR IS_ERR_OR_NULL(const void *ptr);
extern LONG_PTR IS_ERR(void *err);

static inline unsigned short queue_physical_block_size(struct request_queue *q)
{
	return 512;
}

static inline int queue_alignment_offset(struct request_queue *q)
{
	return 0;
}

static inline int queue_io_opt(struct request_queue *q)
{
	return 0;
}

extern struct block_device *blkdev_get_by_path(const char *path, fmode_t mode, void *holder);

extern void hlist_add_head(struct hlist_node *n, struct hlist_head *h);
extern void hlist_del_init(struct hlist_node *entry);
extern int hlist_unhashed(const struct hlist_node *h);
extern void __hlist_del(struct hlist_node *n);

extern unsigned long crc32(const char *s, size_t len);
extern bool lc_is_used(struct lru_cache *lc, unsigned int enr);
extern int fls(int x);
extern char *kstrdup(const char *s, int gfp);

void windrbd_init_netlink(void);
void windrbd_shutdown_netlink(void);

NTSTATUS windrbd_init_wsk(void);
void windrbd_shutdown_wsk(void);

extern int initRegistry(__in PUNICODE_STRING RegistryPath);
extern void delete_block_device(struct kref *kref);

//
//  Lock primitives
//

/* TODO: not referenced */
typedef struct _PTR_ENTRY
{
    SINGLE_LIST_ENTRY   slink;
    void *              ptr;
} PTR_ENTRY, * PPTR_ENTRY;


// linux-2.6.24 define 
// kernel.h 
#if 0
#define INT_MAX		((int)(~0U>>1))
#define INT_MIN		(-INT_MAX - 1)
#define UINT_MAX	(~0U)
#endif

//pagemap.h
#define PAGE_CACHE_SHIFT	PAGE_SHIFT

// Bio.h
#define BIO_MAX_PAGES		256
#define BIO_MAX_SIZE		(BIO_MAX_PAGES << PAGE_CACHE_SHIFT)

#if 0
//asm-x86 , asm-generic 
#define	EDESTADDRREQ	89	/* Destination address required */
#endif


static int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
	sector_t nr_sects, gfp_t gfp_mask, bool discard)
{
	// WDRBD: Not support
	return 0;
}


#define snprintf(a, b, c, args...) scnprintf(a, b, c, ## args)

extern int scnprintf(char * buf, size_t size, const char *fmt, ...);
extern int vscnprintf(char * buf, size_t size, const char *fmt, va_list args);
/* TODO: defined in some windows header (stdio.h) but not in library: */
/* Update: really? was something else (printf) */
size_t windrbd_vsnprintf(char *buf, size_t bufsize, const char *fmt, va_list args);

void list_cut_position(struct list_head *list, struct list_head *head, struct list_head *entry);

static inline unsigned int queue_io_min(struct request_queue *q)
{
	return 0; // dummy: q->limits.io_min;
}

void bdput(struct block_device *this_bdev);

extern int dtt_initialize(void);
extern void dtt_cleanup(void);

struct block_device *bdget(dev_t dev);

	/* TODO: those 3 should become static */
int windrbd_create_windows_device(struct block_device *bdev);
// void windrbd_remove_windows_device(struct block_device *bdev);

int windrbd_mount(struct block_device *dev);
int windrbd_umount(struct block_device *dev);

int windrbd_become_primary(struct drbd_device *device, const char **err_str);
int windrbd_become_secondary(struct drbd_device *device, const char **err_str);

	/* These are WinDRBD specific ioctls. */

int windrbd_inject_faults(int after, enum fault_injection_location where, struct block_device *windrbd_bdev);
int windrbd_process_netlink_packet(void *msg, size_t msg_size);
size_t windrbd_receive_netlink_packets(void *vbuf, size_t remaining_size, u32 portid);
bool windrbd_are_there_netlink_packets(u32 portid);	/* non-blocking peek at netlink packets. Does not consume them. */
int windrbd_join_multicast_group(u32 portid, const char *name, struct _FILE_OBJECT *f);
int windrbd_delete_multicast_groups_for_file(struct _FILE_OBJECT *f);

int windrbd_um_get_next_request(void *buf, size_t max_data_size, size_t *actual_data_size);
int windrbd_um_return_return_value(void *rv_buf);
int windrbd_init_usermode_helper(void);
int windrbd_set_mount_point_for_minor_utf16(int minor, const wchar_t *mount_point);
bool windrbd_has_mount_point(struct block_device *dev);

	/* see windrbd_bootdevice.c */
int create_drbd_resource_from_url(const char *url);
void windrbd_init_boot_device(void);

/* see printk_to_syslog.c */
struct in_addr;

int my_inet_aton(const char *cp, struct in_addr *inp);
char *my_inet_ntoa(struct in_addr *addr);
/* TODO: this doesn't work on ARM (and other big endian architectures) */
/* ugh ... */
#define htons(x) ((((x) & 0xff) << 8) | (((x) & 0xff00) >> 8))

/* Run internal unit tests. */
void windrbd_run_tests(void);
void windrbd_shutdown_tests(void);

int windrbd_rescan_bus(void);
void windrbd_bus_is_ready(void);
int windrbd_wait_for_bus_object(void);

	/* Use those internally. bdget will always create a new
	 * block device. bdput will signal events (primary, capacity)
	 * to make waiting Windows processes terminate.
	 */

void windrbd_bdget(struct block_device *this_bdev);
void windrbd_bdput(struct block_device *this_bdev);

int windrbd_create_windows_device_for_minor(int minor);

/* See drbd_main.c */
int try_to_promote(struct drbd_device *device, LONG_PTR timeout, bool ndelay);

/* See windrbd_bootdevice.c */
void parser_test(void);

/* Debug. Might go away again. */
void enter_interruptible_debug(const char *file, int line, const char *func);
void exit_interruptible_debug(const char *file, int line, const char *func);

#define enter_interruptible() enter_interruptible_debug(__FILE__, __LINE__, __func__)
#define exit_interruptible() exit_interruptible_debug(__FILE__, __LINE__, __func__)

void test_main(const char *arg);

int my_atoi(const char *c);

NTSTATUS get_registry_int(wchar_t *key, int *val_p, int the_default);
NTSTATUS get_registry_long_long(wchar_t *key, unsigned long long *val_p, unsigned long long the_default);

enum kobject_action {
	KOBJ_ADD,
	KOBJ_REMOVE,
	KOBJ_CHANGE,
	KOBJ_MOVE,
	KOBJ_ONLINE,
	KOBJ_OFFLINE,
	KOBJ_BIND,
	KOBJ_UNBIND,
};

/* Not implemented: */

int kobject_uevent(struct kobject *kobj, enum kobject_action action);

/* Implemented. Taken from Linux 5.11 */
size_t strlcpy(char *dest, const char *src, size_t size);

/* Implemented in windrbd_test: base works now from 2 to 36 */
unsigned long long my_strtoull(const char *nptr, const char ** endptr, int base);

int lock_interface(const char *config_key_param);
int windrbd_is_locked(void);

void init_event_log(void);
void set_event_log_threshold(int level);

void windrbd_device_size_change(struct block_device *bdev);
int set_driver_locked_state(int state);

void windrbd_bdev_cork(struct block_device *bdev);
int windrbd_bdev_uncork(struct block_device *bdev);

int windrbd_application_io_suspended(struct block_device *bdev);
void windrbd_suspend_application_io(struct block_device *bdev, const char *msg);
void windrbd_resume_application_io(struct block_device *bdev, const char *msg);

#endif // DRBD_WINDOWS_H
