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

#include "win2003compat.h"

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
#include "wingenl.h"
#include "windrbd/windrbd_ioctl.h"

#include "disp.h"
#include <linux/mempool.h>
#include <ntdddisk.h>
#include <linux/bitops.h>
#include "windrbd_threads.h"

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


void flush_all_cpu_caches(void);

#define smp_mb() flush_all_cpu_caches()
#define smp_rmb() flush_all_cpu_caches()
#define smp_wmb() flush_all_cpu_caches()


#define atomic_t64				LONGLONG

#define	atomic_inc_return(_p)		InterlockedIncrement((LONG volatile*)(_p))
#define	atomic_dec_return(_p)		InterlockedDecrement((LONG volatile*)(_p))
#define atomic_inc(_v)			atomic_inc_return(_v)
#define atomic_dec(_v)			atomic_dec_return(_v)

#define	atomic_inc_return64(_p)		InterlockedIncrement64((unsigned long long volatile*)(_p))
#define	atomic_dec_return64(_p)		InterlockedDecrement64((unsigned long long volatile*)(_p))
#define atomic_inc64(_v)		atomic_inc_return64(_v)
#define atomic_dec64(_v)		atomic_dec_return64(_v)

extern LONG_PTR xchg(LONG_PTR *target, LONG_PTR value);
extern void atomic_set(atomic_t *v, int i);
extern void atomic_add(int i, atomic_t *v);
extern void atomic_add64(LONGLONG a, atomic_t64 *v);
extern int atomic_add_return(int i, atomic_t *v);
extern void atomic_sub(int i, atomic_t *v);
extern void atomic_sub64(LONGLONG a, atomic_t64 *v);
extern int atomic_sub_return(int i, atomic_t *v);
extern LONGLONG atomic_sub_return64(LONGLONG a, atomic_t64 *v);
extern int atomic_dec_and_test(atomic_t *v);
extern int atomic_sub_and_test(int i, atomic_t *v);
extern int atomic_cmpxchg(atomic_t *v, int old, int new);
extern int atomic_read(const atomic_t *v);
extern LONGLONG atomic_read64(const atomic_t64 *v);
extern int atomic_xchg(atomic_t *v, int n);

#define WARN_ON(x)				__noop
#define ATOMIC_INIT(i)			(i)

#define RELATIVE(wait) (-(wait))

#define __init
#define __exit

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define CMD_TIMEOUT_SHORT_DEF		5		/* should be synchronized with defined value in shared_main.h */

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

// from fs.h
/* file is open for reading */
#define FMODE_READ				    0x1
/* file is open for writing */
#define FMODE_WRITE				    0x2
/* File is opened with O_NDELAY (only set for block devices) */
#define FMODE_NDELAY            		    0x40

// from notify.h
#define NOTIFY_DONE				    0x0000          /* Don't care */
#define NOTIFY_OK				    0x0001          /* Suits me */
#define NOTIFY_STOP_MASK			0x8000          /* Don't call further */
#define NOTIFY_BAD				    (NOTIFY_STOP_MASK|0x0002)

/* Those match now the Linux values. Use errno utility to convert number
 * to symbol (or symbol to number).
 */

#include <errno.h>

#if 0
#define EINVAL					22
#define EOPNOTSUPP				95
#define ENOTSUPP				95
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
#define EADDRINUSE             			98
#define	EOVERFLOW				75
#define	ESTALE					11
#define ECONNABORTED				103
#define ENODATA					61
#define ENOTCONN				107
#define EADDRNOTAVAIL				99
#define ENOTSUP					95
#define EACCES					13
#endif

#define ERESTARTSYS				512
#define EMEDIUMTYPE				513	
#define ENOTSUPP				514
#define EHOSTDOWN				515

#define MAX_ERRNO				4095
#define IS_ERR_VALUE(_x)		((_x) >= (ULONG_PTR) -MAX_ERRNO)

// for drbd_actlog.c
// #define __attribute__(packed)
// #define __attribute(packed)
#ifdef LONG_MAX
#undef LONG_MAX
#endif
#define MAX_SCHEDULE_TIMEOUT ((long)(~0UL>>1)) 
#define SENDER_SCHEDULE_TIMEOUT	5 * HZ
#define HZ 1000

/* https://msdn.microsoft.com/en-us/library/64ez38eh.aspx */
#pragma intrinsic(_ReturnAddress)
#define _RET_IP_				((void*)_ReturnAddress())


#define likely(_X)				(_X)
#define unlikely(_X)			(_X)

#define PAGE_KERNEL				1
#define	BIO_UPTODATE			1

#define cond_resched()		    __noop

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

typedef unsigned int                fmode_t;

#define MAX_TEXT_BUF                256

#define MAX_SPLIT_BLOCK_SZ			(1 << 20)

#define FLTR_COMPONENT              DPFLTR_DEFAULT_ID
//#define FLTR_COMPONENT              DPFLTR_IHVDRIVER_ID

extern int initialize_syslog_printk(void);
extern void shutdown_syslog_printk(void);
extern void set_syslog_ip(const char *ip);

extern int _printk(const char * func, const char * format, ...);
extern void printk_reprint(size_t bytes);

struct drbd_device;
void windrbd_device_error(struct drbd_device *device, const char ** err_str_out, const char *fmt, ...);

#define printk(args...)   \
    _printk(__FUNCTION__, args)

#ifdef DEBUG
#define dbg(args...)   \
    _printk(__FUNCTION__, args)
#else
#define dbg(args...)   __noop
#endif

extern int _mem_printk(const char *file, int line, const char *func, const char *fmt, ...);

#define mem_printk(args...)   \
    _mem_printk(__FILE__, __LINE__, __FUNCTION__, args)

extern int debug_printks_enabled;

#define cond_printk(args...) \
	if (debug_printks_enabled) \
		_printk(__FUNCTION__, args)

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

struct block_device_operations {
	struct module *owner;
	void (*submit_bio) (struct bio*);
	int (*open) (struct block_device *, fmode_t);
	void (*release) (struct gendisk *, fmode_t);
};

struct kobj_type {
	void(*release)(struct kobject *);
};

extern sector_t windrbd_get_capacity(struct block_device *bdev);
extern sector_t get_capacity(struct gendisk *disk);

struct bio;

	/* When we create more bio's upon request for a single MDL,
	 * this is common data shared between all that bios.
	 */

struct bio_collection {
	atomic_t bc_num_completed;
	size_t bc_total_size;
	int bc_num_requests;

	int bc_device_failed;
	spinlock_t bc_device_failed_lock;

};

#define BI_WINDRBD_FLAG_BOOTSECTOR_PATCHED 0

void init_free_bios(void);
void shutdown_free_bios(void);

struct bio_set {
	mempool_t *bio_pool;
};

extern struct bio *bio_clone(struct bio *, int x);
/* This is patched out of DRBD, patch it in again when implemented.
 * Careful: this is also a #define in drbd_wrappers expect funny things
 * to happen.
extern struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *bs);
 */
extern struct bio_pair *bio_split(struct bio *bi, int first_sectors);
extern void bio_pair_release(struct bio_pair *dbio);
extern struct bio_set *bioset_create(unsigned int, unsigned int);
extern void bioset_free(struct bio_set *);
#ifdef BIO_ALLOC_DEBUG
extern struct bio *bio_alloc_debug(gfp_t mask, int nr_iovecs, ULONG tag, char *file, int line, char *func);
#define bio_alloc(a, b, c) bio_alloc_debug(a, b, c, __FILE__, __LINE__, __func__)
#else
extern struct bio *bio_alloc(gfp_t, int, ULONG);
#endif

extern struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *unused);


	/* To be called at the beginning of conn_disconnect, else
	 * BSOD.
	 */
extern int wait_for_bios_to_complete(struct block_device *bdev);

#ifdef BIO_REF_DEBUG

extern void bio_get_debug(struct bio *bio, const char *file, int line, const char *func);
extern void bio_put_debug(struct bio *bio, const char *file, int line, const char *func);

#define bio_get(bio) bio_get_debug(bio, __FILE__, __LINE__, __func__)
#define bio_put(bio) bio_put_debug(bio, __FILE__, __LINE__, __func__)
#else
static inline void bio_get(struct bio *bio)
{
	atomic_inc(&bio->bi_cnt);
}
extern void bio_put(struct bio *);
#endif

extern void bio_free(struct bio *bio); 
// extern int bio_add_page(struct bio *bio, struct page *page, unsigned int len,unsigned int offset);
extern int bio_add_page_debug(struct bio *bio, struct page *page, unsigned int len,unsigned int offset, char *file, int line, char *func);
#define bio_add_page(bio, page, len, offset) \
    bio_add_page_debug(bio, page, len, offset, __FILE__, __LINE__, __func__) 
extern void bio_endio(struct bio *bio);

/**
 * bio_start_io_acct - start I/O accounting for bio based drivers
 * @bio:	bio to start account for
 *
 * Returns the start time that should be passed back to bio_end_io_acct().
 * TODO: not implemented.
 */
static inline unsigned long bio_start_io_acct(struct bio *bio)
{
	return 0;
}

/**
 * bio_end_io_acct - end I/O accounting for bio based drivers
 * @bio:	bio to end account for
 * @start:	start time returned by bio_start_io_acct()
 * TODO: not implemented.
 */
static inline void bio_end_io_acct(struct bio *bio, unsigned long start_time)
{
}

int generic_make_request(struct bio *bio);
static inline int submit_bio(struct bio *bio)
{
	return generic_make_request(bio);
}

static inline int submit_bio_noacct(struct bio *bio)
{
	return generic_make_request(bio);
}

/* Attention: The backward comp version of this macro accesses bio from
   calling namespace */
#define bio_iter_last(BVEC, ITER) ((ITER) == bio->bi_vcnt - 1)

// DRBD_DOC: not support, it is always newest updated block for windows.
/* TODO: Sure? */
#define bio_flagged(bio, flag)  (1) 
// #define bio_flagged(bio, flag)  ((bio)->bi_flags & (1 << (flag))) 

extern void sema_init(struct semaphore *s, int limit);

#ifdef KREF_DEBUG

int kref_put_debug(struct kref *kref, void (*release)(struct kref *kref), const char *release_name, const char *file, int line, const char *func, int may_printk);
void kref_get_debug(struct kref *kref, const char *file, int line, const char *func, int may_printk);
void kref_init_debug(struct kref *kref, const char *file, int line, const char *func);

#define kref_put(kref, release) \
	kref_put_debug(kref, release, #release, __FILE__, __LINE__, __func__, 1)

#define kref_get(kref) \
	kref_get_debug(kref, __FILE__, __LINE__, __func__, 1)

#define kref_put_no_printk(kref, release) \
	kref_put_debug(kref, release, #release, __FILE__, __LINE__, __func__, 0)

#define kref_get_no_printk(kref) \
	kref_get_debug(kref, __FILE__, __LINE__, __func__, 0)

#define kref_init(kref) \
	kref_init_debug(kref, __FILE__, __LINE__, __func__)

#else

extern int kref_put(struct kref *kref, void (*release)(struct kref *kref));
extern void kref_get(struct kref *kref);
extern void kref_init(struct kref *kref);

/* See windrbd_winsocket.c */
#define kref_put_no_printk kref_put
#define kref_get_no_printk kref_get

#endif

extern struct request_queue *bdev_get_queue(struct block_device *bdev);
extern void blk_cleanup_queue(struct request_queue *q);
#define NUMA_NO_NODE 0
extern struct request_queue *blk_alloc_queue(int unused);
typedef void (make_request_fn) (struct request_queue *q, struct bio *bio);
extern void blk_queue_make_request(struct request_queue *q, make_request_fn *mfn);
extern void blk_queue_flush(struct request_queue *q, unsigned int flush);

struct queue_limits;

extern void blk_queue_segment_boundary(struct request_queue *, unsigned long);
extern int blk_stack_limits(struct queue_limits *t, struct queue_limits *b,
			    sector_t offset);
extern void blk_queue_update_readahead(struct request_queue *q);

extern struct gendisk *alloc_disk(int minors);
extern void put_disk(struct gendisk *disk);
extern void del_gendisk(struct gendisk *disk);
extern void set_disk_ro(struct gendisk *disk, int flag);

extern struct gendisk *blk_alloc_disk(int unused);
extern void blk_cleanup_disk(struct gendisk *disk);

extern struct block_device *bdget_disk(struct gendisk *disk, int partno);
#define disk_to_dev(disk) \
	(disk)->bdev

extern int fsync_bdev(struct block_device *bdev);

#define PREPARE_WORK(_work, _func)                                      \
	do {                                                            \
		(_work)->func = (_func);                                \
	} while (0)

#define __INIT_WORK(_work, _func, _onstack)                             \
	 do {                                                           \
	       /* __init_work((_work), _onstack);        */  \
	       /*  (_work)->data = (atomic_long_t) WORK_DATA_INIT(); */ \
		INIT_LIST_HEAD(&(_work)->work_list);			\
		spin_lock_init(&(_work)->pending_lock);			\
		PREPARE_WORK((_work), (_func));                         \
		(_work)->pending = 0;					\
	} while (0)

#define INIT_WORK(_work, _func)                                         \
	 __INIT_WORK((_work), (_func), 0);  

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

#define time_after(_a,_b)		((LONG_PTR)((LONG_PTR)(_b) - (LONG_PTR)(_a)) < 0)
#define time_after_eq(_a,_b)		((LONG_PTR)((LONG_PTR)(_a) - (LONG_PTR)(_b)) >= 0)

#define time_before(_a,_b)		time_after(_b, _a)
#define time_before_eq(_a,_b)		time_after_eq(_b, _a)

struct lru_cache;
extern struct lc_element *lc_element_by_index(struct lru_cache *lc, unsigned i);
extern unsigned int lc_index_of(struct lru_cache *lc, struct lc_element *e);

#include <wsk.h>	/* for struct sockaddr_storage */
#include <drbd_transport.h>

void free_page_kref(struct kref *kref);

static inline void put_page(struct page *page)
{
	kref_put(&page->kref, free_page_kref);
}

static inline void get_page(struct page *page)
{
	kref_get(&page->kref);
}

#define page_private(_page)		((_page)->private)
#define set_page_private(_page, _v)	((_page)->private = (_v))

extern void *page_address(const struct page *page);
extern int page_count(struct page *page);
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


struct workqueue_struct *alloc_ordered_workqueue(const char * fmt, int flags, ...);
extern void queue_work(struct workqueue_struct* queue, struct work_struct* work);
extern void flush_workqueue(struct workqueue_struct *wq);
extern void destroy_workqueue(struct workqueue_struct *wq);

extern struct workqueue_struct *system_wq;

static inline void schedule_work(struct work_struct *work)
{
	queue_work(system_wq, work);
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


extern void init_completion_debug(struct completion *c, const char *file, int line, const char *func);
extern void wait_for_completion_debug(struct completion *c, const char *file, int line, const char *func);
extern ULONG_PTR wait_for_completion_timeout_debug(struct completion *c, ULONG_PTR timeout, const char *file, int line, const char *func);
extern void complete_debug(struct completion *c, const char *file, int line, const char *func);
extern void complete_all_debug(struct completion *c, const char *file, int line, const char *func);

#define init_completion(c) init_completion_debug(c, __FILE__, __LINE__, __func__)
#define wait_for_completion(c) wait_for_completion_debug(c, __FILE__, __LINE__, __func__)
#define wait_for_completion_timeout(c, t) wait_for_completion_timeout_debug(c, t, __FILE__, __LINE__, __func__)
#define complete(c) complete_debug(c, __FILE__, __LINE__, __func__)
#define complete_all(c) complete_all_debug(c, __FILE__, __LINE__, __func__)

struct crypto_tfm;
extern void *crypto_alloc_tfm(char *name, u32 mask);
extern unsigned int crypto_tfm_alg_digestsize(struct crypto_tfm *tfm);
extern int generic_make_request(struct bio *bio); // return value is changed for error handling 2015.12.08(DW-649)

extern int call_usermodehelper(char *path, char **argv, char **envp, int wait);

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

extern uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length);
extern unsigned long crc32(const char *s, size_t len);
extern bool lc_is_used(struct lru_cache *lc, unsigned int enr);
extern void get_random_bytes(char *buf, int nbytes);
extern int fls(int x);
struct sk_buff;
extern unsigned char *skb_put(struct sk_buff *skb, unsigned int len);
extern char *kstrdup(const char *s, int gfp);
extern void panic(const char *fmt, ...);

void windrbd_init_netlink(void);
void windrbd_shutdown_netlink(void);

NTSTATUS windrbd_init_wsk(void);
void windrbd_shutdown_wsk(void);

extern int initRegistry(__in PUNICODE_STRING RegistryPath);
extern void delete_block_device(struct kref *kref);

extern void list_add_rcu(struct list_head *new, struct list_head *head);
extern void list_add_tail_rcu(struct list_head *new,   struct list_head *head);
extern void list_del_rcu(struct list_head *entry);

#define bdevname(dev, buf)   dev->bd_disk->disk_name

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

// Bitops.h
#define BITS_PER_BYTE		8

extern void down(struct semaphore *s);
extern int down_trylock(struct semaphore *s);
extern void up(struct semaphore *s);

/* This does not initialize the rw_semaphore (we would need to call
   a Windows API function in the initializer). Initialize it from
   the DriverEntry function.
 */

#define DECLARE_RWSEM(sem) \
	struct rw_semaphore sem;

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

ULONG_PTR find_first_zero_bit(const ULONG_PTR *addr, ULONG_PTR size);
int find_next_zero_bit(const ULONG_PTR * addr, ULONG_PTR size, ULONG_PTR offset);

// for_each_set_bit = find_first_bit + find_next_bit => reference linux 3.x kernel. 
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

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

/* From: include/linux/kdev_t.h : */
#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

int register_blkdev(int major, const char *name);
void unregister_blkdev(int major, const char *name);

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

/* TODO: to another header: */

#define kmap(_page)		(_page->addr)
#define kmap_atomic(_page)	(_page->addr)
#define kunmap(addr)		do { } while (0)
#define kunmap_atomic(addr)	do { } while (0)

void test_main(const char *arg);

int my_atoi(const char *c);

NTSTATUS get_registry_int(wchar_t *key, int *val_p, int the_default);
NTSTATUS get_registry_long_long(wchar_t *key, unsigned long long *val_p, unsigned long long the_default);

	/* can always send page */
static inline bool sendpage_ok(struct page *p)
{
	return 1;
}

	/* There are no read only backing devices */

static inline int bdev_read_only(struct block_device *bdev)
{
	return 0;
}

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
