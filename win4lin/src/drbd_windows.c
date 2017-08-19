/*
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

#include "drbd_windows.h"

#undef _NTDDK_
/* Can't include that without getting redefinition errors.
 *   10.0.14393.0\km\ntddk.h(69): error C2371: 'PEPROCESS': redefinition; different basic types
 *   10.0.14393.0\km\wdm.h(84): note: see declaration of 'PEPROCESS'
#include <ntifs.h>
 *   */
NTSTATUS
NTAPI
ZwCreateEvent (
	_Out_ PHANDLE EventHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ EVENT_TYPE EventType,
	_In_ BOOLEAN InitialState
	);
NTSTATUS
NTAPI
ZwWaitForSingleObject(
	_In_ HANDLE Handle,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
	);

/* same for #include <Winternl.h> */
NTSTATUS NtOpenFile(
  _Out_ PHANDLE            FileHandle,
  _In_  ACCESS_MASK        DesiredAccess,
  _In_  POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_ PIO_STATUS_BLOCK   IoStatusBlock,
  _In_  ULONG              ShareAccess,
  _In_  ULONG              OpenOptions
);


ULONG RtlRandomEx(
  _Inout_ PULONG Seed
);


#include <ntddk.h>
#include <stdint.h>
#include <stdarg.h>
#include <intrin.h>
#include "wsk2.h"
#include "drbd_wingenl.h"
#include "linux/idr.h"
#include "drbd_wrappers.h"
#include "disp.h"
#include "proto.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, do_add_minor)
#endif
long		gLogCnt = 0;
LONGLONG 	gTotalLogCnt = 0;
char		gLogBuf[LOGBUF_MAXCNT][MAX_DRBDLOG_BUF] = {0,};

int g_bypass_level;
int g_read_filter;
int g_mj_flush_buffers_filter;
int g_use_volume_lock;
int g_netlink_tcp_port;
int g_daemon_tcp_port;

// minimum levels of logging, below indicates default values. it can be changed when WDRBD receives IOCTL_MVOL_SET_LOGLV_MIN.
atomic_t g_eventlog_lv_min = LOG_LV_DEFAULT_EVENTLOG;
atomic_t g_dbglog_lv_min = LOG_LV_DEFAULT_DBG;
#ifdef _WIN32_DEBUG_OOS
atomic_t g_oos_trace = 0;
#endif

#ifdef _WIN32_HANDLER_TIMEOUT
int g_handler_use;
int g_handler_timeout;
int g_handler_retry;
#endif

WCHAR g_ver[64];

#define MAX_IDR_SHIFT		(sizeof(int) * 8 - 1)
#define MAX_IDR_BIT		(1U << MAX_IDR_SHIFT)

/* Leave the possibility of an incomplete final layer */
#define MAX_IDR_LEVEL ((MAX_IDR_SHIFT + IDR_BITS - 1) / IDR_BITS)

/* Number of id_layer structs to leave in free list */
#define MAX_IDR_FREE (MAX_IDR_LEVEL * 2)


extern SIMULATION_DISK_IO_ERROR gSimulDiskIoError = {0,};

// DW-1105: monitoring mount change thread state (FALSE : not working, TRUE : working)
atomic_t g_monitor_mnt_working = FALSE;

//__ffs - find first bit in word.
ULONG_PTR __ffs(ULONG_PTR word) 
{
	int num = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

#define ffz(x)  __ffs(~(x))

int fls(int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

#define BITOP_WORD(nr)          ((nr) / BITS_PER_LONG)

ULONG_PTR find_first_bit(const ULONG_PTR* addr, ULONG_PTR size)
{
	const ULONG_PTR* p = addr;
	ULONG_PTR result = 0;
	ULONG_PTR tmp;

	while (size & ~(BITS_PER_LONG - 1)) {
		if ((tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
#ifdef _WIN64
	tmp = (*p) & (~0ULL >> (BITS_PER_LONG - size));
	if (tmp == 0ULL)	{	/* Are any bits set? */
#else
	tmp = (*p) & (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)	{	/* Are any bits set? */
#endif
		return result + size;	/* Nope. */
	}
found:
	return result + __ffs(tmp);
}

ULONG_PTR find_next_bit(const ULONG_PTR *addr, ULONG_PTR size, ULONG_PTR offset)
{
	const ULONG_PTR *p = addr + BITOP_WORD(offset);
	ULONG_PTR result = offset & ~(BITS_PER_LONG - 1);
	ULONG_PTR tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
#ifdef _WIN64
		tmp &= (~0ULL << offset);
#else
		tmp &= (~0UL << offset);
#endif
		if (size < BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG - 1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
#ifdef _WIN64
	tmp &= (~0ULL >> (BITS_PER_LONG - size));
	if (tmp == 0ULL)	/* Are any bits set? */
#else
	tmp &= (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
#endif
		return result + size;	/* Nope. */
found_middle:
	return result + __ffs(tmp);
}

const char _zb_findmap [] = {
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,6,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,5,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,7,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 8 };

static inline ULONG_PTR __ffz_word(ULONG_PTR nr, ULONG_PTR word)
 {
 #ifdef _WIN64
    if ((word & 0xffffffff) == 0xffffffff) {
            word >>= 32;
            nr += 32;
    }
 #endif
    if ((word & 0xffff) == 0xffff) {
            word >>= 16;
            nr += 16;
    }
    if ((word & 0xff) == 0xff) {
            word >>= 8;
            nr += 8;
    }
	return nr + _zb_findmap[(unsigned char) word];
 }
 /*
 * Find the first cleared bit in a memory region.
 */
ULONG_PTR find_first_zero_bit(const ULONG_PTR *addr, ULONG_PTR size)
 {
	const ULONG_PTR *p = addr;
	ULONG_PTR result = 0;
	ULONG_PTR tmp;

	 while (size & ~(BITS_PER_LONG - 1)) {
		 if (~(tmp = *(p++)))
			 goto found;
		 result += BITS_PER_LONG;
		 size -= BITS_PER_LONG;
	 }
	 if (!size)
		 return result;

#ifdef _WIN64
	 tmp = (*p) | (~0ULL << size);
	 if (tmp == ~0ULL)        /* Are any bits zero? */
#else
	 tmp = (*p) | (~0UL << size);
	 if (tmp == ~0UL)        /* Are any bits zero? */
#endif
		 return result + size;        /* Nope. */
 found:
	 return result + ffz(tmp);
 }

int find_next_zero_bit(const ULONG_PTR * addr, ULONG_PTR size, ULONG_PTR offset)
{
	const ULONG_PTR *p;
	ULONG_PTR bit, set;
 
    if (offset >= size)
            return size;
    bit = offset & (BITS_PER_LONG - 1);
    offset -= bit;
    size -= offset;
    p = addr + offset / BITS_PER_LONG;
    if (bit) {
        /*
        * __ffz_word returns BITS_PER_LONG
        * if no zero bit is present in the word.
        */
        set = __ffz_word(bit, *p >> bit);
        if (set >= size)
                return size + offset;
        if (set < BITS_PER_LONG)
                return set + offset;
        offset += BITS_PER_LONG;
        size -= BITS_PER_LONG;
        p++;
    }

    return offset + find_first_zero_bit(p, size);
 }

static int g_test_and_change_bit_flag = 0;
static spinlock_t g_test_and_change_bit_lock;

int test_and_change_bit(int nr, const ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr);
	ULONG_PTR old;
	ULONG_PTR flags;

	if (!g_test_and_change_bit_flag)
	{
		spin_lock_init(&g_test_and_change_bit_lock);
		g_test_and_change_bit_flag = 1;
	}

	spin_lock_irq(&g_test_and_change_bit_lock);
	old = *p;
	*p = old ^ mask;
	spin_unlock_irq(&g_test_and_change_bit_lock);

    return (old & mask) != 0;
}

LONG_PTR xchg(LONG_PTR *target, LONG_PTR value)
{
#ifdef _WIN64
	return (InterlockedExchange64(target, value));
#else
	return (InterlockedExchange(target, value));
#endif
}


void atomic_set(atomic_t *v, int i)
{
	InterlockedExchange((long *)v, i);
}

void atomic_add(int i, atomic_t *v)
{
	InterlockedExchangeAdd((long *)v, i);
}

void atomic_add64(LONGLONG a, atomic_t64 *v)
{
	InterlockedExchangeAdd64((LONGLONG*)v, a);
}

void atomic_sub(int i, atomic_t *v)
{
	atomic_sub_return(i, v);
}

void atomic_sub64(LONGLONG a, atomic_t64 *v)
{
	atomic_sub_return64(a, v);
}

int atomic_sub_return(int i, atomic_t *v)
{
	int retval;
	retval = InterlockedExchangeAdd((LONG*)v, -i);
	retval -= i;
	return retval;
}

LONGLONG atomic_sub_return64(LONGLONG a, atomic_t64 *v)
{
	LONGLONG retval;
	retval = InterlockedExchangeAdd64((LONGLONG*)v, -a);
	retval -= a;
	return retval;
}

int atomic_dec_and_test(atomic_t *v)
{
	return (0 == InterlockedDecrement((LONG*)v));
}

int atomic_sub_and_test(int i, atomic_t *v)
{
	LONG_PTR retval;
	retval = InterlockedExchangeAdd((LONG*)v, -i);
	retval -= i;
	return (retval == 0);
}

int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return InterlockedCompareExchange((long *)v, new, old);
}

int atomic_xchg(atomic_t *v, int n)
{
	return InterlockedExchange((LONG*)v, n);
}

int atomic_read(const atomic_t *v)
{
	return InterlockedAnd((LONG*)v, 0xffffffff);
}

LONGLONG atomic_read64(const atomic_t64 *v)
{
	return InterlockedAnd64((LONGLONG*)v, 0xffffffffffffffff);
}

void * kmalloc(int size, int flag, ULONG Tag)
{
	return kcalloc(size, 1, flag, Tag); // => adjust size, count parameter mismatch
}

void * kcalloc(int size, int count, int flag, ULONG Tag)
{
	return kzalloc(size * count, 0, Tag);
}

void * kzalloc(int size, int flag, ULONG Tag)
{
	void *mem;
    static int fail_count = 0;

	mem = ExAllocatePoolWithTag(NonPagedPool, size, Tag);
	if (!mem)
	{
		return NULL;
	}

	RtlZeroMemory(mem, size);
	return mem;
}

char *kstrdup(const char *s, int gfp)
{
	size_t len;
	char *buf;

	if (!s)
		return NULL;

	len = strlen(s) + 1;
	buf = kzalloc(len, gfp, 'C3DW');
	if (buf)
		memcpy(buf, s, len);
	return buf;
}

void *page_address(const struct page *page)
{
	return page->addr;
}

struct page  *alloc_page(int flag)
{
	struct page *p = kmalloc(sizeof(struct page),0, 'D3DW'); 
	if (!p)	{
		WDRBD_INFO("alloc_page struct page failed\n");
		return NULL;
	}	
	RtlZeroMemory(p, sizeof(struct page));
	
	p->addr = kzalloc(PAGE_SIZE, 0, 'E3DW');
	if (!p->addr)	{
		kfree(p); 
		WDRBD_INFO("alloc_page PAGE_SIZE failed\n");
		return NULL;
	}
	RtlZeroMemory(p->addr, PAGE_SIZE);

	return p;
}

void __free_page(struct page *page)
{
	kfree(page->addr);
	kfree(page); 
}

void drbd_bp(char *msg)
{
    WDRBD_ERROR("breakpoint: msg(%s)\n", msg);
}

__inline void kfree(const void * x)
{
	if (x)
	{
		ExFreePool((void*)x);
	}
}

__inline void kvfree(const void * x)
{
	if (x)
	{
		ExFreePool((void*)x);
	}
}

// from  linux 2.6.32
int kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
#ifdef _WIN32
    WARN_ON(release == NULL);
    WARN_ON(release == (void (*)(struct kref *))kfree);

    if (atomic_dec_and_test(&kref->refcount))
    {
        release(kref);
        return 1;
    }
    return 0;
#else
	kref_sub(kref, 1, release);
#endif
}

int kref_get(struct kref *kref)
{
	return atomic_inc_return(&kref->refcount) < 2;
}

void kref_init(struct kref *kref)
{
	atomic_set(&kref->refcount, 1);
}

struct request_queue *bdev_get_queue(struct block_device *bdev)
{
	if (bdev && bdev->bd_disk) {
		return bdev->bd_disk->queue;
	}

	return NULL;
}

struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *bs)
{
	return NULL;
}

struct bio *bio_alloc(gfp_t gfp_mask, int nr_iovecs, ULONG Tag)
{
	struct bio *bio;

	if(nr_iovecs == 0) { // DW-1242 fix nr_iovecs is zero case.
		return 0;
	}
	
	bio = kzalloc(sizeof(struct bio) + nr_iovecs * sizeof(struct bio_vec), gfp_mask, Tag);
	if (!bio)
	{
		return 0;
	}
	bio->bi_max_vecs = nr_iovecs;
	bio->bi_cnt = 1;
	bio->bi_vcnt = 0;

	if (nr_iovecs > 256)
	{
		WDRBD_ERROR("DRBD_PANIC: bio_alloc: nr_iovecs too big = %d. check over 1MB.\n", nr_iovecs);
		BUG();
	}
	return bio;
}

void bio_put(struct bio *bio)
{
    int cnt;
    cnt = atomic_dec(&bio->bi_cnt);
    if (cnt == 0) {
	bio_free(bio);
    }
}

void bio_free(struct bio *bio)
{
	kfree(bio);
}

void bio_endio(struct bio *bio, int error)
{
    if (bio->bi_end_io) {
	if(error) {
	    WDRBD_INFO("thread(%s) bio_endio error with err=%d.\n", current->comm, error);
	    bio->bi_end_io(bio, error);
	} else { // if bio_endio is called with success(just in case)
	    //WDRBD_INFO("thread(%s) bio_endio with err=%d.\n", current->comm, error);
	    bio->bi_end_io(bio, error);
	}
    }
}

struct bio *bio_clone(struct bio * bio_src, int flag)
{
    struct bio *bio = bio_alloc(flag, bio_src->bi_max_vecs, '24DW');

    if (!bio)
    {
        return NULL;
    }

	memcpy(bio->bi_io_vec, bio_src->bi_io_vec, bio_src->bi_max_vecs * sizeof(struct bio_vec));
	bio->bi_sector = bio_src->bi_sector;
	bio->bi_bdev = bio_src->bi_bdev;
	//bio->bi_flags |= 1 << BIO_CLONED;
	bio->bi_rw = bio_src->bi_rw;
	bio->bi_vcnt = bio_src->bi_vcnt;
	bio->bi_size = bio_src->bi_size;
	bio->bi_idx = bio_src->bi_idx;

	return bio;
}

int bio_add_page(struct bio *bio, struct page *page, unsigned int len,unsigned int offset)
{
	struct bio_vec *bvec = &bio->bi_io_vec[bio->bi_vcnt++];
		
	if (bio->bi_vcnt > 1)
	{
		WDRBD_ERROR("DRBD_PANIC: bio->bi_vcn=%d. multi page occured!\n", bio->bi_vcnt);
        BUG();
	}

	bvec->bv_page = page;
	bvec->bv_len = len;
	bvec->bv_offset = offset;
	bio->bi_size += len;

	return len;
}

#include "drbd_int.h"

long IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long) ptr); 
}

void *ERR_PTR(long error)
{
	return (void *) error;
}

long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

int IS_ERR(void *ptr)
{
	return IS_ERR_VALUE((unsigned long) ptr);
}

void wake_up_process(struct drbd_thread *thi)
{
    KeSetEvent(&thi->wait_event, 0, FALSE);
}

void _wake_up(wait_queue_head_t *q, char *__func, int __line)
{		
    KeSetEvent(&q->wqh_event, 0, FALSE);
}

void wake_up_all(wait_queue_head_t *q)
{
	/* Should cause all threads to wake up and check the condition again */
	/* TODO: phil check whether the single-wake-up is wrong? */
    KeSetEvent(&q->wqh_event, 0, FALSE);
}

void init_completion(struct completion *completion)
{
	memset(completion->wait.eventName, 0, Q_NAME_SZ);
	strcpy(completion->wait.eventName, "completion");
	init_waitqueue_head(&completion->wait);
}

long wait_for_completion(struct completion *completion)
{
	return schedule(&completion->wait, MAX_SCHEDULE_TIMEOUT, __FUNCTION__, __LINE__);
}

long wait_for_completion_timeout(struct completion *completion, long timeout)
{
    return schedule(&completion->wait, timeout, __FUNCTION__, __LINE__);
}

void complete(struct completion *c)
{
    KeSetEvent(&c->wait.wqh_event, 0, FALSE);
}

void complete_all(struct completion *c)
{
    KeSetEvent(&c->wait.wqh_event, 0, FALSE);
}

static  void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new)
{
	list_add(&new->task_list, &head->task_list);
}

long schedule(wait_queue_head_t *q, long timeout, char *func, int line) 
{
	LARGE_INTEGER nWaitTime;
	LARGE_INTEGER *pTime;
	unsigned long expire;

	expire = timeout + jiffies;
	nWaitTime.QuadPart = 0;

	if(timeout != MAX_SCHEDULE_TIMEOUT)
	{
		nWaitTime = RtlConvertLongToLargeInteger((timeout) * (-1 * 1000 * 10));
	}
	else
	{
		nWaitTime = RtlConvertLongToLargeInteger((60) * (-1 * 10000000));
	}
	pTime = &nWaitTime;
	if ((q == NULL) || (q == (wait_queue_head_t *)SCHED_Q_INTERRUPTIBLE))
	{
		KTIMER ktimer;
		KeInitializeTimer(&ktimer);
		KeSetTimer(&ktimer, nWaitTime, 0);
		KeWaitForSingleObject(&ktimer, Executive, KernelMode, FALSE, NULL);
	}
	else
	{
		NTSTATUS status;
		PVOID waitObjects[2] = {0};
		struct task_struct *thread = current;

		int wObjCount = 1;

		waitObjects[0] = (PVOID) &q->wqh_event;
		if (thread->has_sig_event)
		{
			waitObjects[1] = (PVOID) &thread->sig_event;
			wObjCount = 2;
		}

		while (1)
		{
			//HERf("about to wait; count %d, timeout %llu, obj 0x%p 0x%p", wObjCount, (unsigned long long)nWaitTime.QuadPart, waitObjects[0], waitObjects[1]); // too noisy
			status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);

			switch (status) {
			case STATUS_WAIT_0:
				KeResetEvent(&q->wqh_event); // DW-105: use event and polling both.
				break;

			case STATUS_WAIT_1:
				if (thread->sig == DRBD_SIGKILL)
				{
					return -DRBD_SIGKILL;
				}
				break;

			case STATUS_TIMEOUT:
				if (timeout == MAX_SCHEDULE_TIMEOUT)
				{
					continue;
				}
				break;

			default:
				WDRBD_ERROR("DRBD_PANIC: KeWaitForMultipleObjects done! default status=0x%x\n", status);
				BUG();
				break;
			}
			break;
		}
	}

	timeout = expire - jiffies;
	return timeout < 0 ? 0 : timeout;
}
#ifdef _WIN32
int queue_work(struct workqueue_struct* queue, struct work_struct* work)
#else
void queue_work(struct workqueue_struct* queue, struct work_struct* work)
#endif
{
    struct work_struct_wrapper * wr = kmalloc(sizeof(struct work_struct_wrapper), 0, '68DW');
#ifdef _WIN32 // DW-1051	
	if(!wr) {
		return FALSE;
	}
#endif	
    wr->w = work;
    ExInterlockedInsertTailList(&queue->list_head, &wr->element, &queue->list_lock);
    KeSetEvent(&queue->wakeupEvent, 0, FALSE); // signal to run_singlethread_workqueue
#ifdef _WIN32
    return TRUE;
#endif
}
#ifdef _WIN32
void run_singlethread_workqueue(struct workqueue_struct * wq)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID waitObjects[2] = { &wq->wakeupEvent, &wq->killEvent };
    int maxObj = 2;

    while (wq->run)
    {
        status = KeWaitForMultipleObjects(maxObj, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
        switch (status)
        {
            case STATUS_WAIT_0:
            {
                PLIST_ENTRY entry;
                while ((entry = ExInterlockedRemoveHeadList(&wq->list_head, &wq->list_lock)) != 0)
                {
                    struct work_struct_wrapper * wr = CONTAINING_RECORD(entry, struct work_struct_wrapper, element);
                    wr->w->func(wr->w);
                    kfree(wr);
                }
                break;
            }

            case (STATUS_WAIT_1) :
                wq->run = FALSE;
                break;

            default:
                continue;
        }
    }
}

struct workqueue_struct *alloc_ordered_workqueue(const char * fmt, int flags, ...)
{
    struct workqueue_struct * wq = kzalloc(sizeof(struct workqueue_struct), 0, '31DW');
    va_list args;
    va_start(args, flags);
    NTSTATUS status;


    if (!wq)
    {
        return NULL;
    }

    KeInitializeEvent(&wq->wakeupEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&wq->killEvent, SynchronizationEvent, FALSE);
    InitializeListHead(&wq->list_head);
    KeInitializeSpinLock(&wq->list_lock);

    status = RtlStringCbVPrintfA(wq->name, sizeof(wq->name)-1, fmt, args);
    if (status != STATUS_SUCCESS) {
	WDRBD_ERROR("Can't RtlStringCbVPrintfA");
        kfree(wq);
        return NULL;
    }

    wq->run = TRUE;

    HANDLE hThread = NULL;
    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, run_singlethread_workqueue, wq);
    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("PsCreateSystemThread failed with status 0x%08X\n", status);
        kfree(wq);
        return NULL;
    }

    status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &wq->pThread, NULL);
    ZwClose(hThread);
    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("ObReferenceObjectByHandle failed with status 0x%08X\n", status);
        kfree(wq);
        return NULL;
    }

    return wq;
}
#endif
#ifdef _WIN32_TMP_DEBUG_MUTEX
void mutex_init(struct mutex *m, char *name)
#else
void mutex_init(struct mutex *m)
#endif
{
	KeInitializeMutex(&m->mtx, 0);
#ifdef _WIN32_TMP_DEBUG_MUTEX
	memset(m->name, 0, 32);
	strcpy(m->name, name); 
#endif
}

NTSTATUS mutex_lock_timeout(struct mutex *m, ULONG msTimeout)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER nWaitTime = { 0, };

	if (NULL == m)
	{
		return STATUS_INVALID_PARAMETER;
	}

	nWaitTime.QuadPart = (-1 * 10000);
	nWaitTime.QuadPart *= msTimeout;		// multiply timeout value separately to avoid overflow.
	status = KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, &nWaitTime);

	return status;
}

__inline
NTSTATUS mutex_lock(struct mutex *m)
{
    return KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, NULL);
}

__inline
int mutex_lock_interruptible(struct mutex *m)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int err = -EIO;
	struct task_struct *thread = current;
	PVOID waitObjects[2];
	int wObjCount = 1;

	waitObjects[0] = (PVOID)&m->mtx;
	if (thread->has_sig_event)
	{
		waitObjects[1] = (PVOID)&thread->sig_event;
		wObjCount++;
	}
	
	status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, NULL, NULL);

	switch (status)
	{
	case STATUS_WAIT_0:		// mutex acquired.
		err = 0;
		break;
	case STATUS_WAIT_1:		// thread got signal by the func 'force_sig'
		err = thread->sig != 0 ? -thread->sig : -EIO;
		break;
	default:
		err = -EIO;
		WDRBD_ERROR("KeWaitForMultipleObjects returned unexpected status(0x%x)", status);
		break;
	}

	return err;
}

// Returns 1 if the mutex is locked, 0 if unlocked.
int mutex_is_locked(struct mutex *m)
{
	return (KeReadStateMutex(&m->mtx) == 0) ? 1 : 0;
}

// Try to acquire the mutex atomically. 
// Returns 1 if the mutex has been acquired successfully, and 0 on contention.
int mutex_trylock(struct mutex *m)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = 0; 

	if (KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

void mutex_unlock(struct mutex *m)
{
	KeReleaseMutex(&m->mtx, FALSE);
}

void sema_init(struct semaphore *s, int limit)
{
    KeInitializeSemaphore(&s->sem, limit, limit);    
    WDRBD_TRACE_SEM("KeInitializeSemaphore!  KeReadStateSemaphore (%d)\n", KeReadStateSemaphore(&s->sem));
}

void down(struct semaphore *s)
{
    WDRBD_TRACE_SEM("KeWaitForSingleObject before! KeReadStateSemaphore (%d)\n", KeReadStateSemaphore(&s->sem));
    KeWaitForSingleObject(&s->sem, Executive, KernelMode, FALSE, NULL);
    WDRBD_TRACE_SEM("KeWaitForSingleObject after! KeReadStateSemaphore (%d)\n", KeReadStateSemaphore(&s->sem));
}

/**
  * down_trylock - try to acquire the semaphore, without waiting
  * @sem: the semaphore to be acquired
  *
  * Try to acquire the semaphore atomically.  Returns 0 if the semaphore has
  * been acquired successfully or 1 if it it cannot be acquired.
  */

int down_trylock(struct semaphore *s)
{
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = 0;
    
    if (KeWaitForSingleObject(&s->sem, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS)
    {
        WDRBD_TRACE_SEM("success! KeReadStateSemaphore (%d)\n", KeReadStateSemaphore(&s->sem));
        return 0;
    }
    else
    {
        WDRBD_TRACE_SEM("fail! KeReadStateSemaphore (%d)\n", KeReadStateSemaphore(&s->sem));
        return 1;
    }
}

void up(struct semaphore *s)
{
    if (KeReadStateSemaphore(&s->sem) < s->sem.Limit)
    {
        WDRBD_TRACE_SEM("KeReleaseSemaphore before! KeReadStateSemaphore (%d)\n", KeReadStateSemaphore(&s->sem));
        KeReleaseSemaphore(&s->sem, IO_NO_INCREMENT, 1, FALSE);
        WDRBD_TRACE_SEM("KeReleaseSemaphore after! KeReadStateSemaphore (%d)\n", KeReadStateSemaphore(&s->sem));
    }
}

KIRQL du_OldIrql;

void downup_rwlock_init(KSPIN_LOCK* lock)
{
	KeInitializeSpinLock(lock);
}

KIRQL down_write(KSPIN_LOCK* lock)
{
	return KeAcquireSpinLock(lock, &du_OldIrql);
}

void up_write(KSPIN_LOCK* lock)
{
	KeReleaseSpinLock(lock, du_OldIrql);
	return;
}

KIRQL down_read(KSPIN_LOCK* lock)
{
	return KeAcquireSpinLock(lock, &du_OldIrql);
}

void up_read(KSPIN_LOCK* lock)
{
	KeReleaseSpinLock(lock, du_OldIrql);
	return;
}

void spin_lock_init(spinlock_t *lock)
{
	KeInitializeSpinLock(&lock->spinLock);
	lock->Refcnt = 0;
	lock->OwnerThread = 0;
}

void acquireSpinLock(KSPIN_LOCK *lock, KIRQL *flags)
{
	KeAcquireSpinLock(lock, flags);
}

void releaseSpinLock(KSPIN_LOCK *lock, KIRQL flags)
{
	KeReleaseSpinLock(lock, flags);
}

// DW-903 protect lock recursion
// if current thread equal lock owner thread, just increase refcnt

long _spin_lock_irqsave(spinlock_t *lock)
{
	KIRQL	oldIrql = 0;
	PKTHREAD curthread = KeGetCurrentThread();
	if( curthread == lock->OwnerThread) { 
		WDRBD_WARN("thread:%p spinlock recursion is happened! function:%s line:%d\n", curthread, __FUNCTION__, __LINE__);
	} else {
		acquireSpinLock(&lock->spinLock, &oldIrql);
		lock->OwnerThread = curthread;
	}
	InterlockedIncrement(&lock->Refcnt);
	return (long)oldIrql;
}

void spin_lock(spinlock_t *lock)
{
	spin_lock_irq(lock);
}

void spin_unlock(spinlock_t *lock)
{
	spin_unlock_irq(lock);
}

// DW-903 protect lock recursion
// if current thread equal lock owner thread, just increase refcnt

void spin_lock_irq(spinlock_t *lock)
{
	PKTHREAD curthread = KeGetCurrentThread();
	if( curthread == lock->OwnerThread) {//DW-903 protect lock recursion
		WDRBD_WARN("thread:%p spinlock recursion is happened! function:%s line:%d\n", curthread, __FUNCTION__, __LINE__);
	} else {
		acquireSpinLock(&lock->spinLock, &lock->saved_oldIrql);
		lock->OwnerThread = curthread;
	}
	InterlockedIncrement(&lock->Refcnt);
}

// fisrt, decrease refcnt
// If refcnt is 0, clear OwnerThread and release lock

void spin_unlock_irq(spinlock_t *lock)
{
	InterlockedDecrement(&lock->Refcnt);
	if(lock->Refcnt == 0) {
		lock->OwnerThread = 0;
		releaseSpinLock(&lock->spinLock, lock->saved_oldIrql);
	}
}
// fisrt, decrease refcnt
// If refcnt is 0, clear OwnerThread and release lock

void spin_unlock_irqrestore(spinlock_t *lock, long flags)
{
	InterlockedDecrement(&lock->Refcnt);
	if(lock->Refcnt == 0) {
		lock->OwnerThread = 0;
		releaseSpinLock(&lock->spinLock, (KIRQL) flags);
	}
}

// DW-903 protect lock recursion
// if current thread equal lock owner thread, just increase refcnt
void spin_lock_bh(spinlock_t *lock)
{
	PKTHREAD curthread = KeGetCurrentThread();
	if( curthread == lock->OwnerThread) {
		WDRBD_WARN("thread:%p spinlock recursion is happened! function:%s line:%d\n", curthread, __FUNCTION__, __LINE__);
	} else {
		KeAcquireSpinLock(&lock->spinLock, &lock->saved_oldIrql);
		lock->OwnerThread = curthread;
	}
	InterlockedIncrement(&lock->Refcnt);
}
// fisrt, decrease refcnt
// If refcnt is 0, clear OwnerThread and release lock
void spin_unlock_bh(spinlock_t *lock)
{
	InterlockedDecrement(&lock->Refcnt);
	if(lock->Refcnt == 0) {
		lock->OwnerThread = 0;
		KeReleaseSpinLock(&lock->spinLock, lock->saved_oldIrql);
	}
}

spinlock_t g_irqLock;
void local_irq_disable()
{	
	spin_lock_irq(&g_irqLock);
}

void local_irq_enable()
{
	spin_unlock_irq(&g_irqLock);
}

BOOLEAN spin_trylock(spinlock_t *lock)
{
	if (FALSE == KeTestSpinLock(&lock->spinLock))
		return FALSE;
	
	spin_lock(lock);
	return TRUE;
}

void get_random_bytes(char *buf, int nbytes)
{
    static ULONG_PTR lcg_2_64_div_pi = 0;
    static ULONG_PTR mmix_knuth = 0;
    LARGE_INTEGER li;
    ULONG_PTR rnt;
    ULONG rn;
    int length;

    if (mmix_knuth == 0) {
	    li = KeQueryPerformanceCounter(NULL);
	    mmix_knuth = li.QuadPart;
    }
    if (lcg_2_64_div_pi == 0) {
	    lcg_2_64_div_pi = mmix_knuth;
	    get_random_bytes((char*)&lcg_2_64_div_pi, sizeof(lcg_2_64_div_pi));
    }

    /* https://www.winvistatips.com/threads/verifier-exe-is-not-compatible-with-rtlrandom-ex.193117/ */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL) {
	    /* RtlRandomEx only returns [0, 2^31-1], so not even 31bit. */
	    RtlRandomEx(&rn);
	    mmix_knuth += rn;
    }

    while (nbytes > 0)
    {
	    /* https://en.wikipedia.org/wiki/Linear_congruential_generator */
	    mmix_knuth = mmix_knuth * 6364136223846793005 + 1442695040888963407;
	    /* Nearest prime to 2^64/π */
	    lcg_2_64_div_pi = lcg_2_64_div_pi * 5871781006564002809 + 1;

	    /* Hide lowest bits */
	    rn = (lcg_2_64_div_pi ^ mmix_knuth) >> 11;

	    length = sizeof(rn);
	    if (length > nbytes)
		    length = nbytes;

	    memcpy(buf, (UCHAR *)&rn, length);

	    nbytes -= length;
	    buf += length;
    }
}

unsigned int crypto_tfm_alg_digestsize(struct crypto_tfm *tfm)
{
	return 4; // 4byte in constant
}

int page_count(struct page *page)
{
	return 1;
}

static void timer_callback(PKDPC dpc, struct timer_list* timer, PVOID arg1, PVOID arg2)
{
	(void)arg1;
	(void)arg2;
	(void)dpc;
	timer->function(timer->data);
}

void setup_timer(struct timer_list * timer, void(*function)(ULONG_PTR data), ULONG_PTR data)
{
	timer->function = function;
	timer->data = data;
	KeInitializeTimer(&timer->ktimer);
	KeInitializeDpc(&timer->dpc, (PKDEFERRED_ROUTINE)timer_callback, timer);
}

void add_timer(struct timer_list *t)
{
	mod_timer(t, t->expires);
}

void del_timer(struct timer_list *t)
{
	KeCancelTimer(&t->ktimer);
    t->expires = 0;
}

#ifdef _WIN32
/**
 * timer_pending - is a timer pending?
 * @timer: the timer in question
 *
 * timer_pending will tell whether a given timer is currently pending,
 * or not. Callers must ensure serialization wrt. other operations done
 * to this timer, eg. interrupt contexts, or other CPUs on SMP.
 *
 * return value: 1 if the timer is pending, 0 if not.
 */
static __inline int timer_pending(const struct timer_list * timer)
{
    return timer->ktimer.Header.Inserted;
}

int del_timer_sync(struct timer_list *t)
{
#ifdef _WIN32		
	bool pending = 0;
	pending = timer_pending(t);
	
	del_timer(t);

	return pending;
#else
	// from linux kernel 2.6.24
	for (;;) {
		int ret = try_to_del_timer_sync(timer);
		if (ret >= 0)
			return ret;
		cpu_relax();
	}
#endif
}


static int
__mod_timer(struct timer_list *timer, ULONG_PTR expires, bool pending_only)
{
    if (!timer_pending(timer) && pending_only)
    {
		return 0;
    }

    LARGE_INTEGER nWaitTime = { .QuadPart = 0 };
    ULONG_PTR current_milisec = jiffies;

    timer->expires = expires;

    if (current_milisec >= expires)
    {
		nWaitTime.QuadPart = -1;
    }
	else
	{
		expires -= current_milisec;
		nWaitTime = RtlConvertLongToLargeInteger(RELATIVE(MILLISECONDS(expires)));
	}

#ifdef DBG
    WDRBD_TRACE_TM("%s timer(0x%p) current(%d) expires(%d) gap(%d)\n",
        timer->name, timer, current_milisec, timer->expires, timer->expires - current_milisec);
#endif
    KeSetTimer(&timer->ktimer, nWaitTime, &timer->dpc);
    return 1;
}

/**
 * mod_timer_pending - modify a pending timer's timeout
 * @timer: the pending timer to be modified
 * @expires: new timeout in jiffies
 *
 * mod_timer_pending() is the same for pending timers as mod_timer(),
 * but will not re-activate and modify already deleted timers.
 *
 * It is useful for unserialized use of timers.
 */
int mod_timer_pending(struct timer_list *timer, ULONG_PTR expires)
{
    return __mod_timer(timer, expires, true);
}
#endif

int mod_timer(struct timer_list *timer, ULONG_PTR expires)
{
#ifdef _WIN32

	// DW-519 timer logic temporary patch. required fix DW-824. 
    //if (timer_pending(timer) && timer->expires == expires)
    //	return 1;

    return __mod_timer(timer, expires, false);
#else
	LARGE_INTEGER nWaitTime;

	unsigned long current_milisec = jiffies;
	nWaitTime.QuadPart = 0;

	if (current_milisec >= expires_ms)
	{
		nWaitTime.LowPart = 1;
		KeSetTimer(&t->ktimer, nWaitTime, &t->dpc);
		return 0;
	}
	expires_ms -= current_milisec;
	nWaitTime = RtlConvertLongToLargeInteger(-1 * (expires_ms) * 1000 * 10);

	KeSetTimer(&t->ktimer, nWaitTime, &t->dpc);
	return 1;
#endif
}

void kobject_put(struct kobject *kobj)
{
    if (kobj) 
    {
        if (kobj->name == NULL)
        {
            //WDRBD_WARN("%p name is null.\n", kobj);
            return;
        }

		if (atomic_sub_and_test(1, &kobj->kref.refcount))
		{
			void(*release)(struct kobject *kobj);
			release = kobj->ktype->release;
			if (release == 0)
			{
				return;
			}
			release(kobj);
		}
    }
    else
    {
        //WDRBD_WARN("kobj is null.\n");
        return;
    }
}

void kobject_del(struct kobject *kobj)
{
    if (!kobj)
    {
        WDRBD_WARN("kobj is null.\n");
        return;
    }
    kobject_put(kobj->parent); 
}

void kobject_get(struct kobject *kobj)
{
    if (kobj)
    {
        kref_get(&kobj->kref);
    }
    else
    {
        WDRBD_INFO("kobj is null.\n");
        return;
    }
}

void del_gendisk(struct gendisk *disk)
{
	// free disk
}

 void destroy_workqueue(struct workqueue_struct *wq)
{
	 KeSetEvent(&wq->killEvent, 0, FALSE);
	 KeWaitForSingleObject(wq->pThread, Executive, KernelMode, FALSE, NULL);
	 ObDereferenceObject(wq->pThread);
     kfree(wq);
}

 void sock_release(struct socket *sock)
{
	NTSTATUS status;
	
	if (!sock)
	{
		WDRBD_WARN("socket is null.\n");
		return;
	}

#ifndef _WIN32_SEND_BUFFING
	
	status = CloseSocket(sock->sk); 
	if (!NT_SUCCESS(status)) 
	{
		WDRBD_ERROR("error=0x%x\n", status);
		return;
	}
#endif

#ifdef _WIN32_SEND_BUFFING
	struct _buffering_attr *buffering_attr = &sock->buffering_attr;
	struct ring_buffer *bab = buffering_attr->bab;

	if (bab)
	{
		if (bab->static_big_buf)
		{
			kfree(bab->static_big_buf);
		}
		kfree(bab);
	}
	
	status = CloseSocket(sock->sk);
	if (!NT_SUCCESS(status)) {
		return;
	}
#endif

	kfree(sock);
}

//Linux/block/genhd.c
void set_disk_ro(struct gendisk *disk, int flag)
{

}

#define CT_MAX_THREAD_LIST          40
static LIST_HEAD(ct_thread_list);
static int ct_thread_num = 0;
static KSPIN_LOCK ct_thread_list_lock;
static KIRQL ct_oldIrql;

void ct_init_thread_list()
{
    KeInitializeSpinLock(&ct_thread_list_lock);
}

static struct task_struct *__find_thread(PKTHREAD id)
{
    struct task_struct *t;

    list_for_each_entry(struct task_struct, t, &ct_thread_list, list)
    {
        if (t->pid == id) {
            return t;
        }
    }
    return NULL;
}

static void __delete_thread(struct task_struct *t)
{
    list_del(&t->list);
    kfree(t);
    ct_thread_num--;

    // logic check
    if (ct_thread_num < 0)
    {
        WDRBD_ERROR("DRBD_PANIC:unexpected ct_thread_num(%d)\n", ct_thread_num);
        BUG();
    }
}

struct task_struct * ct_add_thread(PKTHREAD id, const char *name, BOOLEAN event, ULONG Tag)
{
    struct task_struct *t;

    if ((t = kzalloc(sizeof(*t), GFP_KERNEL, Tag)) == NULL)
    {
        return NULL;
    }

    t->pid = id;
    if (event)
    {
        KeInitializeEvent(&t->sig_event, SynchronizationEvent, FALSE);
        t->has_sig_event = TRUE;
    }
    strcpy(t->comm, name);
    KeAcquireSpinLock(&ct_thread_list_lock, &ct_oldIrql);
	list_add(&t->list, &ct_thread_list);
	if (++ct_thread_num > CT_MAX_THREAD_LIST) {
        WDRBD_WARN("ct_thread too big(%d)\n", ct_thread_num);
    }
    KeReleaseSpinLock(&ct_thread_list_lock, ct_oldIrql);
    return t;
}

void ct_delete_thread(PKTHREAD id)
{
    KeAcquireSpinLock(&ct_thread_list_lock, &ct_oldIrql);
    __delete_thread(__find_thread(id));
    KeReleaseSpinLock(&ct_thread_list_lock, ct_oldIrql);
}

struct task_struct* ct_find_thread(PKTHREAD id)
{
    struct task_struct *t;
    KeAcquireSpinLock(&ct_thread_list_lock, &ct_oldIrql);
    t = __find_thread(id);
    if (!t)
    {
        static struct task_struct g_dummy_current;
        t = &g_dummy_current;
        t->pid = 0;
        t->has_sig_event = FALSE;
        strcpy(t->comm, "not_drbd_thread");
    }
    KeReleaseSpinLock(&ct_thread_list_lock, ct_oldIrql);
    return t;
}

int signal_pending(struct task_struct *task)
{
    if (task->has_sig_event)
	{
		if (task->sig || KeReadStateEvent(&task->sig_event))
		{
			return 1;
		}
	}
	return 0;
}

void force_sig(int sig, struct task_struct  *task)
{
    if (task->has_sig_event)
	{
		task->sig = sig;
		KeSetEvent(&task->sig_event, 0, FALSE);
	}
}

void flush_signals(struct task_struct *task)
{
    if (task->has_sig_event)
	{
		KeClearEvent(&task->sig_event); 
		task->sig = 0;
	}
}

/* https://msdn.microsoft.com/de-de/library/ff548354(v=vs.85).aspx */
IO_COMPLETION_ROUTINE DrbdIoCompletion;

NTSTATUS DrbdIoCompletion(
  _In_     PDEVICE_OBJECT DeviceObject,
  _In_     PIRP           Irp,
  _In_opt_ PVOID          Context
)
{
    struct bio *bio = Context;

    if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk && bio->bi_bdev->bd_disk->pDeviceExtension) {
	IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
    }

    bio->bi_end_io(bio,
	    Irp->IoStatus.Status == STATUS_SUCCESS ?
	    0 : Irp->IoStatus.Status);

	/* https://msdn.microsoft.com/de-de/library/ff548310(v=vs.85).aspx */
    if (DeviceObject && (DeviceObject->Flags & DO_DIRECT_IO) == DO_DIRECT_IO) {
	PMDL mdl, nextMdl;
	for (mdl = Irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
	    nextMdl = mdl->Next;
	    MmUnlockPages(mdl);
	    IoFreeMdl(mdl); // This function will also unmap pages.
	}
	Irp->MdlAddress = NULL;
    }

//    IoFreeIrp(Irp);

    return STATUS_SUCCESS;
}

int generic_make_request(struct bio *bio)
{
	int err = 0;
	NTSTATUS status = STATUS_SUCCESS;

	PIRP newIrp = NULL;
	PVOID buffer = NULL;;
	LARGE_INTEGER offset = {0,};
	ULONG io = 0;
	PIO_STACK_LOCATION	pIoNextStackLocation = NULL;
	
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);

	if (!q) {
		return -EIO;
	}
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		status = IoAcquireRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
		if (!NT_SUCCESS(status)) {
			WDRBD_ERROR("IoAcquireRemoveLock bio->bi_bdev->bd_disk->pDeviceExtension:%p fail. status(0x%x)\n", bio->bi_bdev->bd_disk->pDeviceExtension, status);
			return -EIO;
		}
	}
	else {
		WDRBD_WARN("IoAcquireRemoveLock IRQL(%d) is too high, bio->pVolExt:%p fail\n", KeGetCurrentIrql(), bio->bi_bdev->bd_disk->pDeviceExtension);
		return -EIO;
	}

	if(bio->bi_rw == WRITE_FLUSH) {
		io = IRP_MJ_FLUSH_BUFFERS;
		buffer = NULL;
		bio->bi_size = 0;
		offset.QuadPart = 0;
	} else {
		if (bio->bi_rw & WRITE) {
			io = IRP_MJ_WRITE;
		} else {
			io = IRP_MJ_READ;
		}
		offset.QuadPart = bio->bi_sector << 9;
		if (bio->bio_databuf) {
			buffer = bio->bio_databuf;
		} else {
			if (bio->bi_max_vecs > 1) {
				BUG(); // DRBD_PANIC
			}
			buffer = (PVOID) bio->bi_io_vec[0].bv_page->addr; 
		}
	}

#ifdef DRBD_TRACE
    WDRBD_TRACE("(%s)Local I/O(%s): sect=0x%llx sz=%d IRQL=%d buf=0x%p, off&=0x%llx target=%c:\n", 
		current->comm, (io == IRP_MJ_READ) ? "READ" : "WRITE", 
		offset.QuadPart / 512, bio->bi_size, KeGetCurrentIrql(), &offset, buffer, q->backing_dev_info.pDeviceExtension->Letter);
#endif

	newIrp = IoBuildAsynchronousFsdRequest(
				io,
				bio->bi_bdev->bd_disk->pDeviceExtension->TargetDeviceObject,
				buffer,
				bio->bi_size,
				&offset,
				NULL
				);

	if (!newIrp) {
		WDRBD_ERROR("IoBuildAsynchronousFsdRequest: cannot alloc new IRP\n");
		IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
		return -ENOMEM;
	}

	if( IRP_MJ_WRITE == io) {
		pIoNextStackLocation = IoGetNextIrpStackLocation (newIrp);
		if(bio->MasterIrpStackFlags) { 
			//copy original Local I/O's Flags for private_bio instead of drbd's write_ordering, because of performance issue. (2016.03.23)
			pIoNextStackLocation->Flags = bio->MasterIrpStackFlags;
		} else { 
			//apply meta I/O's write_ordering
			// DW-1300: get drbd device from gendisk.
			struct drbd_device* device = bio->bi_bdev->bd_disk->drbd_device;
			if(device && device->resource->write_ordering >= WO_BDEV_FLUSH) {
				pIoNextStackLocation->Flags |= (SL_WRITE_THROUGH | SL_FT_SEQUENTIAL_WRITE);
			}
		}
	}

	IoSetCompletionRoutine(newIrp, DrbdIoCompletion, bio, TRUE, TRUE, TRUE);

	//
	//	simulation disk-io error point . (generic_make_request fail) - disk error simluation type 0
	//
	if(gSimulDiskIoError.bDiskErrorOn && gSimulDiskIoError.ErrorType == SIMUL_DISK_IO_ERROR_TYPE0) {
		WDRBD_ERROR("SimulDiskIoError: type0...............\n");
		IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);

		// DW-859: Without unlocking mdl and freeing irp, freeing buffer causes bug check code 0x4e(0x9a, ...)
		// When 'generic_make_request' returns an error code, bi_end_io is called to clean up the bio but doesn't do for irp. We should free irp that is made but wouldn't be delivered.
		// If no error simulation, calling 'IoCallDriver' verifies our completion routine called so that irp will be freed there.
		if (newIrp->MdlAddress != NULL) {
			PMDL mdl, nextMdl;
			for (mdl = newIrp->MdlAddress; mdl != NULL; mdl = nextMdl) {
				nextMdl = mdl->Next;
				MmUnlockPages(mdl);
				IoFreeMdl(mdl); // This function will also unmap pages.
			}
			newIrp->MdlAddress = NULL;
		}
		IoFreeIrp(newIrp);
		return -EIO;
	}
	IoCallDriver(bio->bi_bdev->bd_disk->pDeviceExtension->TargetDeviceObject, newIrp);

	return 0;
}

void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

void list_del_init(struct list_head *entry)
{
	__list_del_entry(entry);
	INIT_LIST_HEAD(entry);
}

int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

void INIT_HLIST_NODE(struct hlist_node *h)
{
    h->next = NULL;
    h->pprev = NULL;
}

void hlist_del_init(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static const u32 crc32c_table[256] = { 
	0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
	0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
	0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
	0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
	0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
	0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
	0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
	0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
	0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
	0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
	0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
	0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
	0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
	0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
	0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
	0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
	0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
	0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
	0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
	0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
	0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
	0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
	0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
	0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
	0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
	0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
	0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
	0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
	0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
	0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
	0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
	0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
	0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
	0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
	0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
	0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
	0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
	0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
	0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
	0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
	0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
	0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
	0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
	0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
	0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
	0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
	0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
	0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
	0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
	0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
	0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
	0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
	0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
	0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
	0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
	0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
	0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
	0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
	0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
	0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
	0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
	0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
	0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
	0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length)
{
	while (length--)
		crc = crc32c_table[(crc ^ *data++) & 0xFFL] ^ (crc >> 8);

	return crc;
}

inline void __list_add_rcu(struct list_head *new, struct list_head *prev, struct list_head *next)
{
	new->next = next;
	new->prev = prev;
	rcu_assign_pointer(list_next_rcu(prev), new);
	next->prev = new;
}

void list_del_rcu(struct list_head *entry)
{
     __list_del(entry->prev, entry->next);
     entry->prev = LIST_POISON2;
}

void list_add_rcu(struct list_head *new, struct list_head *head)
{
    __list_add_rcu(new, head, head->next);
}

void list_add_tail_rcu(struct list_head *new, struct list_head *head)
{
     __list_add_rcu(new, head->prev, head);
}

 struct request_queue *blk_alloc_queue(gfp_t gfp_mask)
 {
     return kzalloc(sizeof(struct request_queue), 0, 'E5DW');
 }

void blk_cleanup_queue(struct request_queue *q)
{
	kfree2(q);
}

struct gendisk *alloc_disk(int minors)
{	
	struct gendisk *p = kzalloc(sizeof(struct gendisk), 0, '44DW');
	return p;
}

void put_disk(struct gendisk *disk)
{
	kfree2(disk);
}

void blk_queue_make_request(struct request_queue *q, make_request_fn *mfn)
{
	// not support
}

void blk_queue_flush(struct request_queue *q, unsigned int flush)
{
}

struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
{
	// not support
	return NULL;
}

void bioset_free(struct bio_set *bs)
{
    /* Will never be called, as bioset_create() above isn't implemented. */
    (void)bs;
}


//
// porting netlink interface 
//
unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = skb_tail_pointer(skb);
	// SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;

	if (skb->tail > skb->end)
	{
#ifndef _WIN32
		// skb_over_panic(skb, len, __builtin_return_address(0));
#else
		WDRBD_ERROR("drbd:skb_put: skb_over_panic\n");
#endif
	}

	return tmp;
}
void *compat_genlmsg_put(struct sk_buff *skb, u32 pid, u32 seq,
				       struct genl_family *family, int flags, u8 cmd)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *hdr;

	nlh = nlmsg_put(skb, pid, seq, family->id, GENL_HDRLEN + family->hdrsize, flags);
	if (nlh == NULL)
		return NULL;

	hdr = nlmsg_data(nlh);
	hdr->cmd = cmd;
	hdr->version = family->version;
	hdr->reserved = 0;

	return (char *) hdr + GENL_HDRLEN;
}

void *genlmsg_put_reply(struct sk_buff *skb,
                         struct genl_info *info,
                         struct genl_family *family,
                         int flags, u8 cmd)
{
#ifndef _WIN32
	return genlmsg_put(skb, info->snd_pid, info->snd_seq, family, flags, cmd);
#else
	return genlmsg_put(skb, info->snd_portid, info->snd_seq, family, flags, cmd);
#endif
}

void genlmsg_cancel(struct sk_buff *skb, void *hdr)
{

}

#ifdef _WIN32 
int _DRBD_ratelimit(struct ratelimit_state *rs, const char * func, const char * __FILE, const int __LINE)
{
	int ret;
	
	if (!rs ||
		!rs->interval)
		return 1;

	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		return 1;
	}

	//If we contend on this state's lock then almost by definition we are too busy to print a message, in addition to the one that will be printed by the entity that is holding the lock already
	if (!spin_trylock(&rs->lock))
		return 0;

	if (!rs->begin)
		rs->begin = jiffies;

	if (time_is_before_jiffies(rs->begin + rs->interval)){
		if (rs->missed)
			WDRBD_WARN("%s(%s@%d): %d callbacks suppressed\n", func, __FILE, __LINE, rs->missed);
		rs->begin = jiffies;
		rs->printed = 0;
		rs->missed = 0;
	}

	if (rs->burst && rs->burst > rs->printed){
		rs->printed++;
		ret = 1;
	} else {
		rs->missed++;
		ret = 0;
	}
	spin_unlock(&rs->lock);

	return ret;
}
#else
int _DRBD_ratelimit(size_t ratelimit_jiffies, size_t ratelimit_burst, struct drbd_conf *mdev, char * __FILE, int __LINE)
{ 
	int __ret;						
	static size_t toks = 0x80000000UL;
	static size_t last_msg; 
	static int missed;			
	size_t now = jiffies;
	toks += now - last_msg;					
	last_msg = now;						
	if (toks > (ratelimit_burst * ratelimit_jiffies))	
		toks = ratelimit_burst * ratelimit_jiffies;	
	if (toks >= ratelimit_jiffies) {

		int lost = missed;				
		missed = 0;					
		toks -= ratelimit_jiffies;			
		if (lost)					
			dev_warn(mdev, "%d messages suppressed in %s:%d.\n", lost, __FILE, __LINE);	
		__ret = 1;					
	}
	else {
		missed++;					
		__ret = 0;					
	}							
	return __ret;							
}
#endif

#ifdef _WIN32
 // disable.
#else
bool _expect(long exp, struct drbd_conf *mdev, char *file, int line)
{
	if (!exp)
	{
		WDRBD_ERROR("minor(%d) ASSERTION FAILED in file:%s line:%d\n", mdev->minor, file, line);
        BUG();
	}
	return exp;
}
#endif
static int idr_max(int layers)
{
	int bits = min_t(int, layers * IDR_BITS, MAX_IDR_SHIFT);
	return (1 << bits) - 1;
}

#ifndef _WIN32
#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#else
#define __round_mask(x, y) ((y) - 1)
#endif
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

void *idr_get_next(struct idr *idp, int *nextidp)
{
	struct idr_layer *p, *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];
	int id = *nextidp;
	int n, max;

	/* find first ent */
	if (!idp)
		return NULL;

	n = idp->layers * IDR_BITS;
	max = 1 << n;
	p = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;

	while (id < max) {
		while (n > 0 && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
		}

		if (p) {
			*nextidp = id;
			return p;
		}

		id += 1 << n;
		while (n < fls(id)) {
			n += IDR_BITS;
			p = *--paa;
		}
	}
	return NULL;
}

/**
 * @brief
 *	Recreate the VOLUME_EXTENSION's MountPoint, VolIndex, block_device
 *	if it was changed
 */
void query_targetdev(PVOLUME_EXTENSION pvext)
{
	if (!pvext) {
		WDRBD_WARN("Null parameter\n");
		return;
	}

	if (IsEmptyUnicodeString(&pvext->VolumeGuid)) {
		// Should be existed guid's name
		mvolQueryMountPoint(pvext);
	}

	UNICODE_STRING new_name;
	NTSTATUS status = RtlVolumeDeviceToDosName(pvext->DeviceObject, &new_name);
	// if not same, it need to re-query
	if (!NT_SUCCESS(status)) {	// ex: CD-ROM
		return;
	}

	// DW-1105: detach volume when replicating volume letter is changed.
	if (pvext->Active &&
		!RtlEqualUnicodeString(&pvext->MountPoint, &new_name, TRUE))
	{
		// DW-1300: get device and get reference.
		struct drbd_device *device = get_device_with_vol_ext(pvext, TRUE);
		if (device &&
			get_ldev_if_state(device, D_NEGOTIATING))
		{
			WDRBD_WARN("replicating volume letter is changed, detaching\n");
			set_bit(FORCE_DETACH, &device->flags);
			change_disk_state(device, D_DETACHING, CS_HARD, NULL);
			put_ldev(device);
		}
		// DW-1300: put device reference count when no longer use.
		if (device)
			kref_put(&device->kref, drbd_destroy_device);
	}

	if (!MOUNTMGR_IS_VOLUME_NAME(&new_name) &&
		!RtlEqualUnicodeString(&new_name, &pvext->MountPoint, TRUE)) {

		FreeUnicodeString(&pvext->MountPoint);
		RtlUnicodeStringInit(&pvext->MountPoint, new_name.Buffer);

		if (IsDriveLetterMountPoint(&new_name)) {
			pvext->VolIndex = pvext->MountPoint.Buffer[0] - 'C';
		}
	}

	// DW-1109: not able to get volume size in add device routine, get it here if no size is assigned.
	if (pvext->dev->bd_contains &&
		pvext->dev->bd_contains->d_size == 0)
	{
		unsigned long long d_size = get_targetdev_volsize(pvext);
		pvext->dev->bd_contains->d_size = d_size;
		pvext->dev->bd_disk->queue->max_hw_sectors =
			d_size ? (d_size >> 9) : DRBD_MAX_BIO_SIZE;
	}
}

// DW-1105: refresh all volumes and handle changes.
void adjust_changes_to_volume(PVOID pParam)
{
	refresh_targetdev_list();
}

// DW-1105: request mount manager to notify us whenever there is a change in the mount manager's persistent symbolic link name database.
void monitor_mnt_change(PVOID pParam)
{
	OBJECT_ATTRIBUTES oaMntMgr = { 0, };
	UNICODE_STRING usMntMgr = { 0, };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hMntMgr = NULL;
	HANDLE hEvent = NULL;
	IO_STATUS_BLOCK iosb = { 0, };
	
	RtlInitUnicodeString(&usMntMgr, MOUNTMGR_DEVICE_NAME);
	InitializeObjectAttributes(&oaMntMgr, &usMntMgr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	do
	{
		status = ZwCreateFile(&hMntMgr,
			FILE_READ_DATA | FILE_WRITE_DATA,
			&oaMntMgr,
			&iosb,
			NULL,
			0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE,
			NULL,
			0);

		if (!NT_SUCCESS(status))
		{
			WDRBD_ERROR("could not open mount manager, status : 0x%x\n", status);
			break;
		}

		status = ZwCreateEvent(&hEvent, GENERIC_ALL, 0, NotificationEvent, FALSE);
		if (!NT_SUCCESS(status))
		{
			WDRBD_ERROR("could not create event, status : 0x%x\n", status);
			break;
		}

		// DW-1105: set state as 'working', this can be set as 'not working' by stop_mnt_monitor.
		atomic_set(&g_monitor_mnt_working, TRUE);

		MOUNTMGR_CHANGE_NOTIFY_INFO mcni1 = { 0, }, mcni2 = { 0, };
		while (TRUE == atomic_read(&g_monitor_mnt_working))
		{
			status = ZwDeviceIoControlFile(hMntMgr, hEvent, NULL, NULL, &iosb, IOCTL_MOUNTMGR_CHANGE_NOTIFY,
				&mcni1, sizeof(mcni1), &mcni2, sizeof(mcni2));

			if (!NT_SUCCESS(status))
			{
				WDRBD_ERROR("ZwDeviceIoControl with IOCTL_MOUNTMGR_CHANGE_NOTIFY has been failed, status : 0x%x\n", status);
				break;
			}
			else if (STATUS_PENDING == status)
			{
				status = ZwWaitForSingleObject(hEvent, TRUE, NULL);
			}

			// we've got notification, refresh all volume and adjust changes if necessary.
			HANDLE hVolRefresher = NULL;
			status = PsCreateSystemThread(&hVolRefresher, THREAD_ALL_ACCESS, NULL, NULL, NULL, adjust_changes_to_volume, NULL);
			if (!NT_SUCCESS(status))
			{
				WDRBD_ERROR("PsCreateSystemThread for adjust_changes_to_volume failed, status : 0x%x\n", status);
				break;
			}

			if (NULL != hVolRefresher)
			{
				ZwClose(hVolRefresher);
				hVolRefresher = NULL;
			}
			
			// prepare for next change.
			mcni1.EpicNumber = mcni2.EpicNumber;
		}

	} while (false);

	atomic_set(&g_monitor_mnt_working, FALSE);

	if (NULL != hMntMgr)
	{
		ZwClose(hMntMgr);
		hMntMgr = NULL;
	}
}

// DW-1105: start monitoring mount change thread.
NTSTATUS start_mnt_monitor()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE	hVolMonitor = NULL;

	status = PsCreateSystemThread(&hVolMonitor, THREAD_ALL_ACCESS, NULL, NULL, NULL, monitor_mnt_change, NULL);
	if (!NT_SUCCESS(status))
	{
		WDRBD_ERROR("PsCreateSystemThread for monitor_mnt_change failed with status 0x%08X\n", status);
		return status;
	}

	if (NULL != hVolMonitor)
	{
		ZwClose(hVolMonitor);
		hVolMonitor = NULL;
	}

	return status;
}

// DW-1105: stop monitoring mount change thread.
void stop_mnt_monitor()
{
	atomic_set(&g_monitor_mnt_working, FALSE);
}

/**
 * @brief
 *	refresh all VOLUME_EXTENSION's values
 */
void refresh_targetdev_list()
{
    PROOT_EXTENSION proot = mvolRootDeviceObject->DeviceExtension;

    MVOL_LOCK();
    for (PVOLUME_EXTENSION pvext = proot->Head; pvext; pvext = pvext->Next) {
        query_targetdev(pvext);
    }
    MVOL_UNLOCK();
}

/**
 * @brief
 */
PVOLUME_EXTENSION get_targetdev_by_minor(unsigned int minor)
{
	char path[3] = { minor_to_letter(minor), ':', '\0' };
	struct block_device * dev = blkdev_get_by_path(path, (fmode_t)0, NULL);
	if (IS_ERR(dev))
	{
		return NULL;
	}

	return dev->bd_disk->pDeviceExtension;
}

/**
 * @return
 *	volume size per byte
 */
LONGLONG get_targetdev_volsize(PVOLUME_EXTENSION VolumeExtension)
{
	LARGE_INTEGER	volumeSize;
	NTSTATUS	status;

	if (!VolumeExtension || VolumeExtension->TargetDeviceObject == NULL)
	{
		WDRBD_ERROR("TargetDeviceObject is null!\n");
		return (LONGLONG)0;
	}
	status = mvolGetVolumeSize(VolumeExtension->TargetDeviceObject, &volumeSize);
	if (!NT_SUCCESS(status))
	{
		WDRBD_WARN("get volume size error = 0x%x\n", status);
		volumeSize.QuadPart = 0;
	}
	return volumeSize.QuadPart;
}

#define DRBD_REGISTRY_VOLUMES       L"\\volumes"

/**
* @brief   create block_device by referencing to VOLUME_EXTENSION object.
*          a created block_device must be freed by ExFreePool() elsewhere.
*/
struct block_device * create_drbd_block_device(IN OUT PVOLUME_EXTENSION pvext)
{
	struct block_device * dev;

	// DW-1109: need to increase reference count of device object to guarantee not to be freed while we're using.
	ObReferenceObject(pvext->DeviceObject);

	dev = kmalloc(sizeof(struct block_device), 0, 'C5DW');
	if (!dev) {
		WDRBD_ERROR("Failed to allocate block_device NonPagedMemory\n");
		return NULL;
	}

	dev->bd_contains = kmalloc(sizeof(struct block_device), 0, 'C5DW');
	if (!dev->bd_contains) {
		WDRBD_ERROR("Failed to allocate block_device NonPagedMemory\n");
		return NULL;
	}

	dev->bd_disk = alloc_disk(0);
	if (!dev->bd_disk)
	{
		WDRBD_ERROR("Failed to allocate gendisk NonPagedMemory\n");
		goto gendisk_failed;
	}

	dev->bd_disk->queue = blk_alloc_queue(0);
	if (!dev->bd_disk->queue)
	{
		WDRBD_ERROR("Failed to allocate request_queue NonPagedMemory\n");
		goto request_queue_failed;
	}

	kref_init(&dev->kref);

	dev->bd_contains->bd_disk = dev->bd_disk;
	dev->bd_contains->bd_parent = dev;

	sprintf(dev->bd_disk->disk_name, "drbd", pvext->VolIndex);
	dev->bd_disk->pDeviceExtension = pvext;

	dev->bd_disk->queue->logical_block_size = 512;

	return dev;

request_queue_failed:
	kfree(dev->bd_disk);

gendisk_failed:
	kfree(dev);

	return NULL;
}

// DW-1109: delete drbd bdev when ref cnt gets 0, clean up all resources that has been created in create_drbd_block_device.
void delete_drbd_block_device(struct kref *kref)
{
	struct block_device *bdev = container_of(kref, struct block_device, kref);

	// DW-1109: reference count has been increased when we create block device, decrease here.
	ObDereferenceObject(bdev->bd_disk->pDeviceExtension->DeviceObject);
	bdev->bd_disk->pDeviceExtension->DeviceObject = NULL;

	// DW-1381: set dev as NULL not to access from this volume extension since it's being deleted.
	bdev->bd_disk->pDeviceExtension->dev = NULL;

	blk_cleanup_queue(bdev->bd_disk->queue);

	put_disk(bdev->bd_disk);

	kfree2(bdev->bd_contains);
	kfree2(bdev);
}

// get device with volume extension in safe, user should put ref when no longer use device.
struct drbd_device *get_device_with_vol_ext(PVOLUME_EXTENSION pvext, bool bCheckRemoveLock)
{
	unsigned char oldIRQL = 0;
	struct drbd_device *device = NULL;

	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		return NULL;

	// DW-1381: dev is set as NULL when block device is destroyed.
	if (!pvext->dev)
	{
		WDRBD_ERROR("failed to get drbd device since pvext->dev is NULL\n");
		return NULL;		
	}

	// DW-1381: check if device is removed already.
	if (bCheckRemoveLock)
	{
		NTSTATUS status = IoAcquireRemoveLock(&pvext->RemoveLock, NULL);
		if (!NT_SUCCESS(status))
		{
			WDRBD_INFO("failed to acquire remove lock with status:0x%x, return NULL\n", status);
			return NULL;
		}
	}

	oldIRQL = ExAcquireSpinLockShared(&pvext->dev->bd_disk->drbd_device_ref_lock);
	device = pvext->dev->bd_disk->drbd_device;
	if (device)
	{
		if (kref_get(&device->kref))
		{
			// already destroyed.
			atomic_dec(&device->kref);			
			device = NULL;
		}
	}
	ExReleaseSpinLockShared(&pvext->dev->bd_disk->drbd_device_ref_lock, oldIRQL);

	if (bCheckRemoveLock)
		IoReleaseRemoveLock(&pvext->RemoveLock, NULL);

	return device;
}

/**
* @brief  get letter from  minor and than return registry status 
*/
BOOLEAN do_add_minor(unsigned int minor)
{
    OBJECT_ATTRIBUTES           attributes;
    PKEY_FULL_INFORMATION       keyInfo = NULL;
    PKEY_VALUE_FULL_INFORMATION valueInfo = NULL;
    size_t                      valueInfoSize = sizeof(KEY_VALUE_FULL_INFORMATION) + 1024 + sizeof(ULONGLONG);
    NTSTATUS                    status;
    HANDLE                      hKey = NULL;
    ULONG                       size;
    int                         count;
    bool                        ret = FALSE;

    PROOT_EXTENSION             prext = mvolRootDeviceObject->DeviceExtension;

    PAGED_CODE();

    PWCHAR new_reg_buf = (PWCHAR)ExAllocatePoolWithTag(PagedPool, MAX_TEXT_BUF, '93DW');
    if (!new_reg_buf)
    {
        WDRBD_ERROR("Failed to ExAllocatePoolWithTag new_reg_buf\n", 0);
        return FALSE;
    }

    UNICODE_STRING new_reg = {0, MAX_TEXT_BUF, new_reg_buf};
	if (!prext->RegistryPath.Buffer) {
		goto cleanup;
	}
    RtlCopyUnicodeString(&new_reg, &prext->RegistryPath);
    RtlAppendUnicodeToString(&new_reg, DRBD_REGISTRY_VOLUMES);

    InitializeObjectAttributes(&attributes,
        &new_reg,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &attributes);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = ZwQueryKey(hKey, KeyFullInformation, NULL, 0, &size);
    if (status != STATUS_BUFFER_TOO_SMALL)
    {
        ASSERT(!NT_SUCCESS(status));
        goto cleanup;
    }

    keyInfo = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, size, 'A3DW');
    if (!keyInfo)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        WDRBD_ERROR("Failed to ExAllocatePoolWithTag() size(%d)\n", size);
        goto cleanup;
    }

    status = ZwQueryKey(hKey, KeyFullInformation, keyInfo, size, &size);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    count = keyInfo->Values;

    valueInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoSize, 'B3DW');
    if (!valueInfo)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        WDRBD_ERROR("Failed to ExAllocatePoolWithTag() valueInfoSize(%d)\n", valueInfoSize);
        goto cleanup;
    }

    for (int i = 0; i < count; ++i)
    {
        RtlZeroMemory(valueInfo, valueInfoSize);

        status = ZwEnumerateValueKey(hKey, i, KeyValueFullInformation, valueInfo, valueInfoSize, &size);

        if (!NT_SUCCESS(status))
        {
            if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL)
            {
                goto cleanup;
            }
        }

        if (REG_BINARY == valueInfo->Type)
        {
            valueInfo->Name[0] &= ~0x20;

            if (minor == valueInfo->Name[0] - L'C')
            {
                ret = true;
                goto cleanup;
            }
        }
    }

cleanup:
    kfree(new_reg_buf);
    kfree(keyInfo);
    kfree(valueInfo);

    if (hKey)
    {
        ZwClose(hKey);
    }

    return ret;
}

/**
 * @brief
 *	link is below 
 *	- "\\\\?\\Volume{d41d41d1-17fb-11e6-bb93-000c29ac57ee}\\"
 *	- "d" or "d:"
 *	- "c/vdrive" or "c\\vdrive"
 *	f no block_device allocated, then query
 */
struct block_device *blkdev_get_by_link(UNICODE_STRING * name)
{
	ROOT_EXTENSION * proot = mvolRootDeviceObject->DeviceExtension;
	VOLUME_EXTENSION * pvext = proot->Head;

printk(KERN_INFO "in blkdev_get_by_link()\n");
printk(KERN_INFO "name: %S\n", name->Buffer);
printk(KERN_INFO "pvext: %p\n", pvext);
	MVOL_LOCK();
	for (; pvext; pvext = pvext->Next) {

printk(KERN_INFO "pvext\n");
		// if no block_device instance yet,
		query_targetdev(pvext);
printk(KERN_INFO "pvext name = %S\n", pvext->PhysicalDeviceName);

		if (RtlEqualMemory(name->Buffer,
			    pvext->PhysicalDeviceName,
			    pvext->PhysicalDeviceNameLength)) {
			break;
		}
	}
	MVOL_UNLOCK();

	return (pvext) ? pvext->dev : NULL;
}

struct block_device *blkdev_get_by_path(const char *path, fmode_t mode, void *holder)
{
	UNREFERENCED_PARAMETER(mode);
	UNREFERENCED_PARAMETER(holder);

	ANSI_STRING apath;
	UNICODE_STRING upath;
	OBJECT_ATTRIBUTES device_attributes;
	NTSTATUS status;
	HANDLE blkdev_handle;
	IO_STATUS_BLOCK io_status_block;

	RtlInitAnsiString(&apath, path);
	status = RtlAnsiStringToUnicodeString(&upath, &apath, TRUE);
	if (!NT_SUCCESS(status)) {
		WDRBD_WARN("RtlAnsiStringToUnicodeString: Cannot convert path to Unicode string, status = %d, path = %s\n", status, path);
		return ERR_PTR(-EINVAL);
	}

	InitializeObjectAttributes(&device_attributes, &upath, OBJ_FORCE_ACCESS_CHECK, NULL, NULL);
	status = NtOpenFile(&blkdev_handle, FILE_READ_DATA | FILE_WRITE_DATA, &device_attributes, &io_status_block, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
	RtlFreeUnicodeString(&upath);

	if (!NT_SUCCESS(status)) {
		WDRBD_WARN("NtOpenFile: Cannot open backing device, status = %d, path = %s\n", status, path);
		return ERR_PTR(-ENODEV);
	}

/* TODO: Check if symbolic link (?) */

/* TODO: create_drbd_block device. Here we need to keep references internally
   with the blkdev_handle and the created drbd device in case the same device
   is opened twice. */
	printk(KERN_INFO "NtOpenFile succeeded. path: %s io_status_block.Information: %d\n", path, io_status_block.Information); 
	printk(KERN_INFO "TODO: create drbd block dev. We now have a handle leak.\n");

	return ERR_PTR(-ENODEV);
}


int call_usermodehelper(char *path, char **argv, char **envp, enum umh_wait wait)
{
	SOCKADDR_IN		LocalAddress = { 0 }, RemoteAddress = { 0 };
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		Socket = NULL;
	char *cmd_line;
	int leng;
	char ret = 0;

	if (0 == g_handler_use)
	{
		return -1;
	}

	leng = strlen(path) + 1 + strlen(argv[0]) + 1 + strlen(argv[1]) + 1 + strlen(argv[2]) + 1;
	cmd_line = kcalloc(leng, 1, 0, '64DW');
	if (!cmd_line)
	{
		WDRBD_ERROR("malloc(%d) failed", leng);
		return -1;
	}

    sprintf(cmd_line, "%s %s\0", argv[1], argv[2]); // except "drbdadm.exe" string
    WDRBD_INFO("malloc len(%d) cmd_line(%s)\n", leng, cmd_line);

    Socket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
	if (Socket == NULL) {
		WDRBD_ERROR("CreateSocket() returned NULL\n");
		kfree(cmd_line);
		return -1; 
	}

	LocalAddress.sin_family = AF_INET;
	LocalAddress.sin_addr.s_addr = INADDR_ANY;
	LocalAddress.sin_port = 0; 

	Status = Bind(Socket, (PSOCKADDR) &LocalAddress);
	if (!NT_SUCCESS(Status)) {
		goto error;
	}

	RemoteAddress.sin_family = AF_INET;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b1 = 127;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b2 = 0;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b3 = 0;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b4 = 1;
	RemoteAddress.sin_port = HTONS(g_daemon_tcp_port); 

	Status = Connect(Socket, (PSOCKADDR) &RemoteAddress);
	if (!NT_SUCCESS(Status)) {
		goto error;;
	}
	else if (Status == STATUS_TIMEOUT)
	{
		WDRBD_INFO("Connect() timeout. IRQL(%d)\n", KeGetCurrentIrql());
		goto error;
	}

	WDRBD_INFO("Connected to the %u.%u.%u.%u:%u  status:0x%08X IRQL(%d)\n", 
			RemoteAddress.sin_addr.S_un.S_un_b.s_b1,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b2,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b3,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b4,
			HTONS(RemoteAddress.sin_port),
			Status, KeGetCurrentIrql());

	{
		LONG readcount;
		char hello[2];
		WDRBD_TRACE("Wait Hi\n");
		if ((readcount = Receive(Socket, &hello, 2, 0, g_handler_timeout)) == 2)
		{
			WDRBD_TRACE("recv HI!!! \n");
			//CloseSocket(Socket);
			//kfree(cmd_line);
			//return ret; 
		}
		else
		{
			if (readcount == -EAGAIN)
			{
				WDRBD_INFO("error rx hi timeout(%d) g_handler_retry(%d) !!!!\n", g_handler_timeout, g_handler_retry);
			}
			else
			{
				WDRBD_INFO("error recv status=0x%x\n", readcount);
			}
			ret = -1;

			// _WIN32_HANDLER_TIMEOUT
			goto error;
		}

#ifdef _WIN32
		if ((Status = SendLocal(Socket, cmd_line, strlen(cmd_line), 0, g_handler_timeout)) != (long) strlen(cmd_line))
#endif
		{
			WDRBD_ERROR("send command fail stat=0x%x\n", Status);
			ret = -1;
			goto error;
		}

		//WDRBD_INFO("send local done %s! Disconnect\n", Status);
		//Disconnect(Socket);

		if ((readcount = Receive(Socket, &ret, 1, 0, g_handler_timeout)) > 0)
		{
			WDRBD_TRACE("recv val=0x%x\n", ret);
			//CloseSocket(Socket);
			//kfree(cmd_line);
			//return ret; 
		}
		else
		{
			if (readcount == -EAGAIN)
			{
				WDRBD_INFO("recv retval timeout(%d)!\n", g_handler_timeout);
			}
			else
			{
			
				WDRBD_INFO("recv status=0x%x\n", readcount);
			}
			ret = -1;
			goto error;
		}

#ifdef _WIN32
		if ((Status = SendLocal(Socket, "BYE", 3, 0, g_handler_timeout)) != 3)
#endif
		{
			WDRBD_ERROR("send bye fail stat=0x%x\n", Status); // ignore!
		}

		WDRBD_TRACE("Disconnect:shutdown...\n", Status);
		Disconnect(Socket);

		/*
		if ((readcount = Receive(Socket, &ret, 1, 0, 0)) > 0)
		{
			WDRBD_INFO("recv dummy  val=0x%x\n", ret);// ignore!
		}
		else
		{
			WDRBD_INFO("recv dummy  status=%d\n", readcount);// ignore!
		}
		*/
	}

error:
	CloseSocket(Socket);
	kfree(cmd_line);
	return ret;
}

void panic(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	printk(fmt, args);
	va_end(args);
	KeBugCheckEx(0xddbd, (ULONG_PTR)__FILE__, (ULONG_PTR)__func__, 0x12345678, 0xd8bdd8bd);
}

int scnprintf(char * buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i = 0;

	va_start(args, fmt);
    i = _vsnprintf_s(buf, size, _TRUNCATE, fmt, args);
	va_end(args);
	return (-1 == i) ? (size - 1) : i;
}

int list_is_singular(const struct list_head *head)
{
	return !list_empty(head) && (head->next == head->prev);
}

void __list_cut_position(struct list_head *list, struct list_head *head, struct list_head *entry)
{
	struct list_head *new_first = entry->next;
	list->next = head->next;
	list->next->prev = list;
	list->prev = entry;
	entry->next = list;
	head->next = new_first;
	new_first->prev = head;
}
// from linux kernel 3.14 
void list_cut_position(struct list_head *list, struct list_head *head, struct list_head *entry)
{
	if (list_empty(head))
		return;
	if (list_is_singular(head) &&
		(head->next != entry && head != entry))
		return;
	if (entry == head)
		INIT_LIST_HEAD(list);
	else
		__list_cut_position(list, head, entry);
}

int drbd_backing_bdev_events(struct gendisk *device)
{
    /* TODO */
#if 0
#ifdef _WIN32_GetDiskPerf
	extern NTSTATUS mvolGetDiskPerf(PDEVICE_OBJECT TargetDeviceObject, PDISK_PERFORMANCE pDiskPerf);
	NTSTATUS status;
	DISK_PERFORMANCE diskPerf;

	status = mvolGetDiskPerf(mdev->ldev->backing_bdev->bd_disk->pDeviceExtension->TargetDeviceObject, &diskPerf);
	if (!NT_SUCCESS(status))
	{
		WDRBD_ERROR("mvolGetDiskPerf status=0x%x\n", status);
		return mdev->writ_cnt + mdev->read_cnt;
	}
	// WDRBD_INFO("mdev: %d + %d = %d, diskPerf: %lld + %lld = %lld\n",
	//		mdev->read_cnt, mdev->writ_cnt, mdev->writ_cnt + mdev->read_cnt,
	//		diskPerf.BytesRead.QuadPart/512, diskPerf.BytesWritten.QuadPart/512,
	//		diskPerf.BytesRead.QuadPart/512 + diskPerf.BytesWritten.QuadPart/512);

	return (diskPerf.BytesRead.QuadPart / 512) + (diskPerf.BytesWritten.QuadPart / 512);
#else
	if ((device->writ_cnt + device->read_cnt) == 0)
	{
		// initial value
		return 100;
	}
	return device->writ_cnt + device->read_cnt;
#endif
#endif
	return 0;
}

char * get_ip4(char *buf, struct sockaddr_in *sockaddr)
{
	sprintf(buf, "%u.%u.%u.%u:%u\0",
		sockaddr->sin_addr.S_un.S_un_b.s_b1,
		sockaddr->sin_addr.S_un.S_un_b.s_b2,
		sockaddr->sin_addr.S_un.S_un_b.s_b3,
		sockaddr->sin_addr.S_un.S_un_b.s_b4,
		HTONS(sockaddr->sin_port)
		);
	return buf;
}
#ifdef _WIN32
char * get_ip6(char *buf, struct sockaddr_in6 *sockaddr)
{
	sprintf(buf, "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u\0", 
			sockaddr->sin6_addr.u.Byte[0],
			sockaddr->sin6_addr.u.Byte[1],
			sockaddr->sin6_addr.u.Byte[2],
			sockaddr->sin6_addr.u.Byte[3],
			sockaddr->sin6_addr.u.Byte[4],
			sockaddr->sin6_addr.u.Byte[5],
			sockaddr->sin6_addr.u.Byte[6],
			sockaddr->sin6_addr.u.Byte[7],
			sockaddr->sin6_addr.u.Byte[8],
			sockaddr->sin6_addr.u.Byte[9],
			sockaddr->sin6_addr.u.Byte[10],
			sockaddr->sin6_addr.u.Byte[11],
			sockaddr->sin6_addr.u.Byte[12],
			sockaddr->sin6_addr.u.Byte[13],
			sockaddr->sin6_addr.u.Byte[14],
			sockaddr->sin6_addr.u.Byte[15],
			HTONS(sockaddr->sin6_port)
			);
	return buf;
}
#endif

struct blk_plug_cb *blk_check_plugged(blk_plug_cb_fn unplug, void *data,
				      int size)
{
#ifndef _WIN32
	struct blk_plug *plug = current->plug;
	struct blk_plug_cb *cb;

	if (!plug)
		return NULL;

	list_for_each_entry(struct blk_plug_cb, cb, &plug->cb_list, list)
		if (cb->callback == unplug && cb->data == data)
			return cb;

	/* Not currently on the callback list */
	BUG_ON(size < sizeof(*cb));
	cb = kzalloc(size, GFP_ATOMIC, 'D8DW');
	if (cb) {
		cb->data = data;
		cb->callback = unplug;
		list_add(&cb->list, &plug->cb_list);
	}
	return cb;
#else
	return NULL;
#endif
}
/* Save current value in registry, this value is used when drbd is loading.*/
NTSTATUS SaveCurrentValue(PCWSTR valueName, int value)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PROOT_EXTENSION pRootExtension = NULL;
	UNICODE_STRING usValueName = { 0, };
	OBJECT_ATTRIBUTES oa = { 0, };
	HANDLE hKey = NULL;

	if (NULL == mvolRootDeviceObject ||
		NULL == mvolRootDeviceObject->DeviceExtension)
	{
		return STATUS_UNSUCCESSFUL;
	}

	do
	{
		pRootExtension = mvolRootDeviceObject->DeviceExtension;

		InitializeObjectAttributes(&oa, &pRootExtension->RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		RtlInitUnicodeString(&usValueName, valueName);
		status = ZwSetValueKey(hKey, &usValueName, 0, REG_DWORD, &value, sizeof(value));
		if (!NT_SUCCESS(status))
		{
			break;
		}

	} while (FALSE);

	if (NULL != hKey)
	{
		ZwClose(hKey);
		hKey = NULL;
	}

	return status;
}

sector_t wdrbd_get_capacity(struct block_device *bdev)
{
    if (!bdev) {
        WDRBD_WARN("Null argument\n");
        return 0;
    }

    if (bdev->d_size) {
        return bdev->d_size >> 9;
    }

    if (bdev->bd_contains) {    // not real device
        bdev = bdev->bd_contains;
        if (bdev->d_size) {
            return bdev->d_size >> 9;
        }
    }

    // Maybe... need to recalculate volume size
    PVOLUME_EXTENSION pvext = (bdev->bd_disk) ? bdev->bd_disk->pDeviceExtension : NULL;
    if (!pvext && (KeGetCurrentIrql() < 2)) {
        bdev->d_size = get_targetdev_volsize(pvext);    // real size
    }

    return bdev->d_size >> 9;
}


int win_drbd_thread_setup(struct drbd_thread *thi)
{
	struct drbd_resource *resource = thi->resource;
	struct drbd_connection *connection = thi->connection;
	int res;

	thi->nt = ct_add_thread(KeGetCurrentThread(), thi->name, TRUE, 'B0DW');
	if (!thi->nt)
	{
		WDRBD_ERROR("DRBD_PANIC: ct_add_thread failed.\n");
		PsTerminateSystemThread(STATUS_SUCCESS);
	}

	KeSetEvent(&thi->start_event, 0, FALSE);
	KeWaitForSingleObject(&thi->wait_event, Executive, KernelMode, FALSE, NULL);

	res = thi->function(thi);
	// TODO ct_delete_thread(thi->task->pid); ??
	if (res)
		WDRBD_ERROR("stop, result %d\n", res);
	else
		WDRBD_INFO("stopped.\n");

	PsTerminateSystemThread(STATUS_SUCCESS);

	return STATUS_SUCCESS;
}

struct block_device *bdget(int dev)
{
	struct block_device *bdev = kzalloc(sizeof(*bdev), 0, 'DBDW');

	(void)dev;

	kref_init(&bdev->kref);
	kref_get(&bdev->kref);
	return bdev;
}

static void _bdput(struct kref *kref)
{
	struct block_device *bdev = container_of(kref, struct block_device, kref);

	kfree(bdev->bd_contains);
	if (bdev != bdev->bd_contains)
		kfree(bdev);
}

void bdput(struct block_device *this_bdev)
{
	kref_put(&this_bdev->kref, _bdput);
}
