/* Uncomment this if you want more debug output (disable for releases) */
/* #define DEBUG 1 */

#ifdef RELEASE
#ifdef DEBUG
#undef DEBUG
#endif
#endif

#include <linux/list.h>
#include "drbd_windows.h"

#define DESC_SIZE 64
#define FUNC_SIZE 32
#define ADDRESS_SIZE 32

#define POISON_BEFORE 0x6ae48807
#define POISON_AFTER 0xfe4a5109

static LIST_HEAD(memory_allocations);
static spinlock_t memory_lock;

struct memory {
	struct list_head list;
	size_t size;
	char address[ADDRESS_SIZE];
	char desc[DESC_SIZE];
	char func[FUNC_SIZE];
	char desc_freed[DESC_SIZE];
	char func_freed[FUNC_SIZE];
	int pad;
	int poison;
	char data[0];	/* this must be 16-byte aligned */
		/* and another poison after that */
};

struct poison_after {
	int poison2;
};

static int kmalloc_errors = 0;
static int print_kmalloc_error = 0;

void *kmalloc_debug(size_t size, int flag, const char *file, int line, const char *func)
{
	struct memory *mem;
	struct poison_after *poison_after;
	size_t full_size;
	KIRQL flags;

// mem_printk("kmalloc %d bytes from %s:%d (%s())\n", size, file, line, func);

#if 0
	if (kmalloc_errors > 0) {

			/* Don't print all the time, since printk itself
			 * also kmalloc's.
			 */

		if (print_kmalloc_error % 10 == 0)
			printk("%d kmalloc errors so far (%d)\n", kmalloc_errors, print_kmalloc_error);
		print_kmalloc_error++;
	}
#endif

	full_size = sizeof(struct memory) + size + sizeof(struct poison_after);
	mem = ExAllocatePoolWithTag(NonPagedPool, full_size, 'DRBD');

	if (mem == NULL) {
		if (strcmp(func, "SendTo") != 0)
			printk("kmalloc_debug: Warning: cannot allocate memory of size %d, %d bytes requested by function %s at %s:%d.\n", full_size, size, func, file, line);

		kmalloc_errors++;
		return NULL;
	}

	mem->size = size;
	snprintf(mem->desc, ARRAY_SIZE(mem->desc), "%s:%d", file, line);
	snprintf(mem->func, ARRAY_SIZE(mem->func), "%s", func);
	snprintf(mem->desc_freed, ARRAY_SIZE(mem->desc), "(not yet freed)");
	snprintf(mem->func_freed, ARRAY_SIZE(mem->func), "(not yet freed)");
	snprintf(mem->address, ARRAY_SIZE(mem->address), "ADDR: %p", &mem->data[0]);
	mem->poison = POISON_BEFORE;

	poison_after = (struct poison_after*) (&mem->data[size]);
	poison_after->poison2 = POISON_AFTER;

	spin_lock_irqsave(&memory_lock, flags);
	list_add(&mem->list, &memory_allocations);
	spin_unlock_irqrestore(&memory_lock, flags);

// mem_printk("kmalloc(%d) = %p from %s:%d %s()\n", size, &mem->data[0], file, line, func);

	return &mem->data[0];
}

void *kzalloc_debug(size_t size, int flag, const char *file, int line, const char *func)
{
	void *data;

	data = kmalloc_debug(size, flag, file, line, func);
	if (data != NULL) {
// mem_printk("memset %p 0 %d called from %s:%d %s()\n", data, size, file, line, func);
		memset(data, 0, size);
	}

	return data;
}

void kfree_debug(const void *data, const char *file, int line, const char *func)
{
	struct memory *mem;
	struct poison_after *poison_after;
	KIRQL flags;
	bool is_double_free = false;

// mem_printk("kfree(%p) %s:%d (%s)\n", data, file, line, func);

	if (data == NULL) {
		dbg("kmalloc_debug: Warning: attempt to free the NULL pointer in function %s at %s:%d\n", func, file, line);
		return;
	}
	mem = container_of((void*) data, struct memory, data);
	poison_after = (struct poison_after*) (&mem->data[mem->size]);

	if (mem->poison != POISON_BEFORE) {
		printk("kmalloc_debug: Warning: Poison before overwritten (is %x should be %x), allocated from %s %s(), freed from %s:%d %s() pointer is %p\n", mem->poison, POISON_BEFORE, mem->desc, mem->func, file, line, func, data);
		if (mem->poison == 'EERF') {
			printk("This is most likely a double free.\n");
			printk("Previously freed from %s %s()\n", mem->desc_freed, mem->func_freed);
/* Buffer is tmp_buffer of SendTo(), see windrbd_winsocket.c */
// printk("data is %.64s\n", mem->data);
		}
	}

	if (poison_after->poison2 != POISON_AFTER) {
		printk("kmalloc_debug: Warning: Poison after overwritten (is %x should be %x), allocated from %s %s(), freed from %s:%d %s() pointer is %p\n", poison_after->poison2, POISON_AFTER, mem->desc, mem->func, file, line, func, data);
		if (poison_after->poison2 == 'EERF') {
			printk("This is most likely a double free.\n");
			printk("(Not freeing that memory again)\n");
			printk("Previously freed from %s %s()\n", mem->desc_freed, mem->func_freed);
			is_double_free = true;
// printk("data is %.64s\n", mem->data);
		}
	}
	if (is_double_free) {
		printk("We think that this a double free, not touching memory again.\n");
		return;
	}

	spin_lock_irqsave(&memory_lock, flags);
	list_del(&mem->list);
	spin_unlock_irqrestore(&memory_lock, flags);

	mem->poison = 'EERF';
	poison_after->poison2 = 'EERF';

	snprintf(mem->desc_freed, ARRAY_SIZE(mem->desc), "%s:%d", file, line);
	snprintf(mem->func_freed, ARRAY_SIZE(mem->func), "%s", func);

	memset(mem->data, 'x', mem->size);
// { char *p; size_t i; for (i=0;i<mem->size;i++) {mem->data[i]='x';} }

// mem_printk("ExFreePool(%p) %s:%d (%s)\n", mem, file, line, func);
	ExFreePool((void*)mem);
}

void init_kmalloc_debug(void)
{
	spin_lock_init(&memory_lock);
	memory_lock.printk_lock = true;
}

#ifdef KMALLOC_DEBUG

int dump_memory_allocations(int free_them)
{
	struct memory *mem, *memh;

/* TODO: spin_lock(&memory_lock)? but then we maybe don't see the printk's ... */

	list_for_each_entry_safe(struct memory, mem, memh, &memory_allocations, list) {
			/* exclude memory needed by printk() */
		if (strcmp(mem->func, "SendTo") != 0 && strcmp(mem->func, "sock_create_linux_socket") != 0) {
			printk("kmalloc_debug: %s of size %d, allocated by function %s at %s mem is %p.\n", free_them ? "Warning: memory leak" : "allocated memory", mem->size, mem->func, mem->desc, mem);
			if (free_them)
				kfree_debug(&mem->data[0], __FILE__, __LINE__, __func__);
		}	/* else we are currently printing this, do not free,
			 * also do not do any more printk's.
			 */
	}
	return 0;
}


int check_memory_allocations(const char *msg)
{
	struct memory *mem, *memh;
	struct poison_after *poison_after;
	int num_corrupted = 0;
	KIRQL flags;

// printk("checking memory %s ...\n", msg);

	spin_lock_irqsave(&memory_lock, flags);
	list_for_each_entry_safe(struct memory, mem, memh, &memory_allocations, list) {
			/* exclude memory needed by printk() */
		if (strcmp(mem->func, "SendTo") != 0 && strcmp(mem->func, "sock_create_linux_socket") != 0) {
			poison_after = (struct poison_after*) (&mem->data[mem->size]);

			if (mem->poison != POISON_BEFORE) {
				printk("kmalloc_debug: %s Warning: Poison before overwritten (is %x should be %x), allocated from %s %s() memory is %p data is %p\n", msg, mem->poison, POISON_BEFORE, mem->desc, mem->func, mem, &mem->data);
				if (mem->poison == 'EERF') {
					printk("This is most likely a double free.\n");
					printk("Previously freed from %s %s()\n", mem->desc_freed, mem->func_freed);
/* Buffer is tmp_buffer of SendTo(), see windrbd_winsocket.c */
// printk("data is %.64s\n", mem->data);
				}
				num_corrupted++;
			}
			if (poison_after->poison2 != POISON_AFTER) {
				printk("kmalloc_debug: %s Warning: Poison after overwritten (is %x should be %x), allocated from %s %s() memory is %p data is %p", msg, poison_after->poison2, POISON_AFTER, mem->desc, mem->func, mem, &mem->data);
				if (poison_after->poison2 == 'EERF') {
					printk("This is most likely a double free.\n");
					printk("(Not freeing that memory again)\n");
					printk("Previously freed from %s %s()\n", mem->desc_freed, mem->func_freed);
				}
				num_corrupted++;
			}
		}
	}
	spin_unlock_irqrestore(&memory_lock, flags);

	if (num_corrupted > 0)
		printk("%d memory corruptions detected.\n", num_corrupted);

	return num_corrupted;
}

#endif

void shutdown_kmalloc_debug(void)
{
	dump_memory_allocations(1);
}
