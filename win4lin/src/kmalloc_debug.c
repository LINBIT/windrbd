#include <linux/list.h>
#include "drbd_windows.h"

#define DESC_SIZE 64
#define FUNC_SIZE 32

#define POISON_BEFORE 0x6ae48807
#define POISON_AFTER 0xfe4a5109

static LIST_HEAD(memory_allocations);
static spinlock_t memory_lock;

struct memory {
	struct list_head list;
	size_t size;
	char desc[DESC_SIZE];
	char func[FUNC_SIZE];
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
	ULONG_PTR flags;

	if (kmalloc_errors > 0) {

			/* Don't print all the time, since printk itself
			 * also kmalloc's.
			 */

		if (print_kmalloc_error % 10 == 0)
			printk("%d kmalloc errors so far (%d)\n", kmalloc_errors, print_kmalloc_error);
		print_kmalloc_error++;
	}

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
	mem->poison = POISON_BEFORE;

	poison_after = (struct poison_after*) (&mem->data[size]);
	poison_after->poison2 = POISON_AFTER;

	spin_lock_irqsave(&memory_lock, flags);
	list_add(&mem->list, &memory_allocations);
	spin_unlock_irqrestore(&memory_lock, flags);

	return &mem->data[0];
}

void *kzalloc_debug(size_t size, int flag, const char *file, int line, const char *func)
{
	void *data;

	data = kmalloc_debug(size, flag, file, line, func);
	if (data != NULL)
		memset(data, 0, size);

	return data;
}

void kfree_debug(const void *data, const char *file, int line, const char *func)
{
	struct memory *mem;
	struct poison_after *poison_after;
	ULONG_PTR flags;

	if (data == NULL) {
		printk("kmalloc_debug: Warning: attempt to free the NULL pointer in function %s at %s:%d\n", func, file, line);
		return;
	}
	mem = container_of((void*) data, struct memory, data);
	poison_after = (struct poison_after*) (&mem->data[mem->size]);

	if (mem->poison != POISON_BEFORE)
		printk("kmalloc_debug: Warning: Poison before overwritten (is %x should be %x)\n", mem->poison, POISON_BEFORE);
	if (poison_after->poison2 != POISON_AFTER)
		printk("kmalloc_debug: Warning: Poison before overwritten (is %x should be %x)\n", poison_after->poison2, POISON_AFTER);

	spin_lock_irqsave(&memory_lock, flags);
	list_del(&mem->list);
	spin_unlock_irqrestore(&memory_lock, flags);

	ExFreePool((void*)mem);
}

void init_kmalloc_debug(void)
{
	spin_lock_init(&memory_lock);
}

int dump_memory_allocations(int free_them)
{
	struct memory *mem, *memh;

	list_for_each_entry_safe(struct memory, mem, memh, &memory_allocations, list) {
			/* exclude memory needed by printk() */
		if (strcmp(mem->func, "SendTo") != 0 && strcmp(mem->func, "sock_create_linux_socket") != 0) {
			printk("kmalloc_debug: %s of size %d, allocated by function %s at %s.\n", free_them ? "Warning: memory leak" : "allocated memory", mem->size, mem->func, mem->desc);
			if (free_them)
				kfree_debug(&mem->data[0], __FILE__, __LINE__, __func__);
		}	/* else we are currently printing this, do not free,
			 * also do not do any more printk's.
			 */
	}
	return 0;
}

void shutdown_kmalloc_debug(void)
{
	dump_memory_allocations(1);
}
