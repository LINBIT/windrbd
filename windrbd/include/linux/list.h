#ifndef __LIST_H__
#define __LIST_H__

#include <linux/stddef.h>
#include <linux/container_of.h>
#include <linux/compiler.h>

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

#define list_entry(ptr, type, member)		container_of(ptr, type, member)
#define list_first_entry(ptr, type, member)	list_entry((ptr)->next, type, member)

#define LIST_HEAD_INIT(name)			{ &(name), &(name) }
#define LIST_HEAD(name)				struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
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

static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

/**
 * list_is_head - tests whether @list is the list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int list_is_head(const struct list_head *list, const struct list_head *head)
{
	return list == head;
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
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void list_del_init(struct list_head *entry)
{
	__list_del_entry(entry);
	INIT_LIST_HEAD(entry);
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

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member) \
		for (pos = list_entry((head)->next, typeof(*pos), member);	\
				&pos->member != (head); 	\
				pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)			\
		for (pos = list_entry((head)->prev, typeof(*pos), member);	\
		     prefetch(pos->member.prev), &pos->member != (head); 	\
		     pos = list_entry(pos->member.prev, typeof(*pos), member))

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
#define list_for_each_entry_rcu(pos, head, member) \
    list_for_each_entry(pos, head, member)

#define list_prepare_entry(pos, head, member) \
         ((pos) ? pos : list_entry(head, typeof(*pos), member))

/**
 * list_for_each_entry_continue - continue iteration over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define list_for_each_entry_continue(pos, head, member) 		\
		for (pos = list_entry(pos->member.next, typeof(*pos), member);	\
		     prefetch(pos->member.next), &pos->member != (head);	\
		     pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)                  \
			for (pos = list_entry((head)->next, typeof(*pos), member),      \
						n = list_entry(pos->member.next, typeof(*pos), member); \
					&pos->member != (head);                                    \
					pos = n, n = list_entry(n->member.next, typeof(*pos), member))
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
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
		for (n = list_entry(pos->member.next, typeof(*pos), member);		\
				&pos->member != (head);						\
				pos = n, n = list_entry(n->member.next, typeof(*pos), member))

#define list_first_entry_or_null(ptr, type, member) \
	(list_empty(ptr) ? NULL : list_first_entry(ptr, type, member))

#include <linux/rculist.h>

/*
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

/**
 * hlist_unhashed - Has node been removed from list and reinitialized?
 * @h: Node to be checked
 *
 * Not that not all removal functions will leave a node in unhashed
 * state.  For example, hlist_nulls_del_init_rcu() does leave the
 * node in unhashed state, but hlist_nulls_del() does not.
 */
static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

/**
 * hlist_unhashed_lockless - Version of hlist_unhashed for lockless use
 * @h: Node to be checked
 *
 * This variant of hlist_unhashed() must be used in lockless contexts
 * to avoid potential load-tearing.  The READ_ONCE() is paired with the
 * various WRITE_ONCE() in hlist helpers that are defined below.
 */
static inline int hlist_unhashed_lockless(const struct hlist_node *h)
{
	return !READ_ONCE(h->pprev);
}

/**
 * hlist_empty - Is the specified hlist_head structure an empty hlist?
 * @h: Structure to check.
 */
static inline int hlist_empty(const struct hlist_head *h)
{
	return !READ_ONCE(h->first);
}

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;

	WRITE_ONCE(*pprev, next);
	if (next)
		WRITE_ONCE(next->pprev, pprev);
}

/**
 * hlist_del - Delete the specified hlist_node from its list
 * @n: Node to delete.
 *
 * Note that this function leaves the node in hashed state.  Use
 * hlist_del_init() or similar instead to unhash @n.
 */
static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

/**
 * hlist_del_init - Delete the specified hlist_node from its list and initialize
 * @n: Node to delete.
 *
 * Note that this function leaves the node in unhashed state.
 */
static inline void hlist_del_init(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

/**
 * hlist_add_head - add a new entry at the beginning of the hlist
 * @n: new entry to be added
 * @h: hlist head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	WRITE_ONCE(n->next, first);
	if (first)
		WRITE_ONCE(first->pprev, &n->next);
	WRITE_ONCE(h->first, n);
	WRITE_ONCE(n->pprev, &h->first);
}

/**
 * hlist_add_before - add a new entry before the one specified
 * @n: new entry to be added
 * @next: hlist node to add it before, which must be non-NULL
 */
static inline void hlist_add_before(struct hlist_node *n,
				    struct hlist_node *next)
{
	WRITE_ONCE(n->pprev, next->pprev);
	WRITE_ONCE(n->next, next);
	WRITE_ONCE(next->pprev, &n->next);
	WRITE_ONCE(*(n->pprev), n);
}

/**
 * hlist_add_behind - add a new entry after the one specified
 * @n: new entry to be added
 * @prev: hlist node to add it after, which must be non-NULL
 */
static inline void hlist_add_behind(struct hlist_node *n,
				    struct hlist_node *prev)
{
	WRITE_ONCE(n->next, prev->next);
	WRITE_ONCE(prev->next, n);
	WRITE_ONCE(n->pprev, &prev->next);

	if (n->next)
		WRITE_ONCE(n->next->pprev, &n->next);
}

/**
 * hlist_add_fake - create a fake hlist consisting of a single headless node
 * @n: Node to make a fake list out of
 *
 * This makes @n appear to be its own predecessor on a headless hlist.
 * The point of this is to allow things like hlist_del() to work correctly
 * in cases where there is no list.
 */
static inline void hlist_add_fake(struct hlist_node *n)
{
	n->pprev = &n->next;
}

/**
 * hlist_fake: Is this node a fake hlist?
 * @h: Node to check for being a self-referential fake hlist.
 */
static inline bool hlist_fake(struct hlist_node *h)
{
	return h->pprev == &h->next;
}

/**
 * hlist_is_singular_node - is node the only element of the specified hlist?
 * @n: Node to check for singularity.
 * @h: Header for potentially singular list.
 *
 * Check whether the node is the only node of the head without
 * accessing head, thus avoiding unnecessary cache misses.
 */
static inline bool
hlist_is_singular_node(struct hlist_node *n, struct hlist_head *h)
{
	return !n->next && n->pprev == &h->first;
}

/**
 * hlist_move_list - Move an hlist
 * @old: hlist_head for old list.
 * @new: hlist_head for new list.
 *
 * Move a list from one list head to another. Fixup the pprev
 * reference of the first entry if it exists.
 */
static inline void hlist_move_list(struct hlist_head *old,
				   struct hlist_head *new)
{
	new->first = old->first;
	if (new->first)
		new->first->pprev = &new->first;
	old->first = NULL;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

/**
 * hlist_for_each_entry	- iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_continue - iterate over a hlist continuing after current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(pos, member)			\
	for (pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_from - iterate over a hlist continuing from current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(pos, member)				\
	for (; pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		a &struct hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });			\
	     pos = hlist_entry_safe(n, typeof(*pos), member))

/**
 * list_is_singular - tests whether a list has just one entry.
 * @head: the list to test.
 */
static inline int list_is_singular(const struct list_head *head)
{
	return !list_empty(head) && (head->next == head->prev);
}

static inline void __list_cut_position(struct list_head *list,
		struct list_head *head, struct list_head *entry)
{
	struct list_head *new_first = entry->next;
	list->next = head->next;
	list->next->prev = list;
	list->prev = entry;
	entry->next = list;
	head->next = new_first;
	new_first->prev = head;
}

/**
 * list_cut_position - cut a list into two
 * @list: a new list to add all removed entries
 * @head: a list with entries
 * @entry: an entry within head, could be the head itself
 *	and if so we won't cut the list
 *
 * This helper moves the initial part of @head, up to and
 * including @entry, from @head to @list. You should
 * pass on @entry an element you know is on @head. @list
 * should be an empty list or a list you do not care about
 * losing its data.
 *
 */
static inline void list_cut_position(struct list_head *list,
		struct list_head *head, struct list_head *entry)
{
	if (list_empty(head))
		return;
	if (list_is_singular(head) && !list_is_head(entry, head) && (entry != head->next))
		return;
	if (list_is_head(entry, head))
		INIT_LIST_HEAD(list);
	else
		__list_cut_position(list, head, entry);
}

#endif
