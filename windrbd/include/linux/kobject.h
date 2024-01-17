#ifndef _KOBJECT_H
#define _KOBJECT_H

#include <linux/kref.h>

struct kobject {
    const char          *name;
    struct kobject      *parent;
    struct kobj_type    *ktype;
    struct kref         kref;
};

#endif
