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

void *kmalloc_debug(size_t size, int flag, const char *file, int line, const char *func)
{
	struct memory *mem;
	struct poison_after *poison_after;
	size_t full_size;
	ULONG_PTR flags;

	full_size = sizeof(struct memory) + size + sizeof(struct poison_after);
	mem = ExAllocatePoolWithTag(NonPagedPool, full_size, 'DRBD');

	if (mem == NULL)
		return NULL;

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

void shutdown_kmalloc_debug(void)
{
	struct memory *mem, *memh;

	list_for_each_entry_safe(struct memory, mem, memh, &memory_allocations, list) {
		printk("kmalloc_debug: Warning: memory leak of size %d, allocated by function %s at %s.\n", mem->size, mem->func, mem->desc);
		kfree_debug(&mem->data[0], __FILE__, __LINE__, __func__);
	}
}

