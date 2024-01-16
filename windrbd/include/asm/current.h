#ifndef _ASM_WINDRBD_CURRENT_H
#define _ASM_WINDRBD_CURRENT_H

#include "windrbd.h"	/* required for windrbd_find_thread() */

#define current	windrbd_find_thread(KeGetCurrentThread())

#endif
