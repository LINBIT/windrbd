#ifndef __LINUX_RCULIST_H
#define __LINUX_RCULIST_H

/**
 * list_entry_rcu - get the struct for this entry
 * @ptr:        the &struct list_head pointer.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define list_entry_rcu(ptr, type, member) \
	container_of(READ_ONCE(ptr), type, member)

/**
 * list_first_or_null_rcu - get the first element from a list
 * @ptr:        the list head to take the element from.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define list_first_or_null_rcu(ptr, type, member) \
({ \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = READ_ONCE(__ptr->next); \
	likely(__ptr != __next) ? list_entry_rcu(__next, type, member) : NULL; \
})

/**
 * list_for_each_entry_continue_rcu - continue iteration over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position which must have been in the list when the RCU read
 * lock was taken.
 * This would typically require either that you obtained the node from a
 * previous walk of the list in the same RCU read-side critical section, or
 * that you held some sort of non-RCU reference (such as a reference count)
 * to keep the node alive *and* in the list.
 *
 * This iterator is similar to list_for_each_entry_from_rcu() except
 * this starts after the given position and that one starts at the given
 * position.
 */
#define list_for_each_entry_continue_rcu(pos, head, member) 		\
	for (pos = list_entry_rcu(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);	\
	     pos = list_entry_rcu(pos->member.next, typeof(*pos), member))


#endif
