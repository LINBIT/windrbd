#ifndef __LIST_H__
#define __LIST_H__

#include <linux/stddef.h>

#ifdef CONFIG_ILLEGAL_POINTER_VALUE
#define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)
#else
#define POISON_POINTER_DELTA		0
#endif

#define LIST_POISON1			0 
#define LIST_POISON2			0 

struct list_head {
	struct list_head *next, *prev;
};

extern void list_del_init(struct list_head *entry);

#define list_entry(ptr, type, member)		container_of(ptr, type, member)
#define list_first_entry(ptr, type, member)	list_entry((ptr)->next, type, member)

#define LIST_HEAD_INIT(name)			{ &(name), &(name) }
#define LIST_HEAD(name)				struct list_head name = LIST_HEAD_INIT(name)

static __inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void list_move(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add(list, head);
}

static inline void list_move_tail(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add_tail(list, head);
}

static inline void __list_splice(const struct list_head *list, struct list_head *prev, struct list_head *next)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;
	last->next = next;
	next->prev = last;
}

static inline void list_splice_init(struct list_head *list, struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head, head->next);
		INIT_LIST_HEAD(list);
	}
}

/**
* list_splice_tail_init - join two lists and reinitialise the emptied list
* @list: the new list to add.
* @head: the place to add it in the first list.
*
* Each of the lists is a queue.
* The list at @list is reinitialised
*/
static inline void list_splice_tail_init(struct list_head *list,
                        struct list_head *head)
{
    if (!list_empty(list))
    {
        __list_splice(list, head->prev, head);
        INIT_LIST_HEAD(list);
    }
}

static inline int list_empty_careful(const struct list_head *head)
{
     struct list_head *next = head->next;
     return (next == head) && (next == head->prev);
}

static inline int list_is_last(const struct list_head *list, const struct list_head *head)
{
	return list->next == head;
}

#define prefetch(_addr)		(_addr)

/**
* list_for_each_entry_rcu	-	iterate over rcu list of given type
* @pos:	the type * to use as a loop cursor.
* @head:	the head for your list.
* @member:	the name of the list_struct within the struct.
*
* This list-traversal primitive may safely run concurrently with
* the _rcu list-mutation primitives such as list_add_rcu()
* as long as the traversal is guarded by rcu_read_lock().
*/
#define list_for_each_entry_rcu(type, pos, head, member) \
    list_for_each_entry(type, pos, head, member)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(type, pos, head, member) \
		for (pos = list_entry((head)->next, type, member);	\
				&pos->member != (head); 	\
				pos = list_entry(pos->member.next, type, member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_reverse(type, pos, head, member)			\
		for (pos = list_entry((head)->prev, type, member);	\
		     prefetch(pos->member.prev), &pos->member != (head); 	\
		     pos = list_entry(pos->member.prev, type, member))

#define list_prepare_entry(type, pos, head, member) \
         ((pos) ? pos : list_entry(head, type, member))

/**
 * list_for_each_entry_continue - continue iteration over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define list_for_each_entry_continue(type, pos, head, member) 		\
		for (pos = list_entry(pos->member.next, type, member);	\
		     prefetch(pos->member.next), &pos->member != (head);	\
		     pos = list_entry(pos->member.next, type, member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(type, pos, n, head, member)                  \
			for (pos = list_entry((head)->next, type, member),      \
						n = list_entry(pos->member.next, type, member); \
					&pos->member != (head);                                    \
					pos = n, n = list_entry(n->member.next, type, member))
/**
 * list_for_each_entry_safe_from
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type from current point, safe against
 * removal of list entry.
 */
#define list_for_each_entry_safe_from(type, pos, n, head, member) 			\
		for (n = list_entry(pos->member.next, type, member);		\
				&pos->member != (head);						\
				pos = n, n = list_entry(n->member.next, type, member))

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)
#endif
