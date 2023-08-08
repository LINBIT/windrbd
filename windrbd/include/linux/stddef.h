#ifndef __STDDEF_H
#define __STDDEF_H

/*
enum {
        false   = 0,
        true    = 1
};
*/
// #define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)

/**
 * offsetofend(TYPE, MEMBER)
 *
 * @TYPE: The type of the structure
 * @MEMBER: The member within the structure to get the end offset of
 */
#define offsetofend(TYPE, MEMBER) \
        (offsetof(TYPE, MEMBER) + sizeof(((TYPE *)0)->MEMBER))


#endif
