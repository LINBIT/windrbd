#ifndef VERSION_H
#define VERSION_H

#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))

/* We take definitions from a 6.5 kernel. Reason is that
 * this should be supported until 2033 (some extra long
 * LTS.
 */
#define LINUX_VERSION_CODE KERNEL_VERSION(6, 5, 13)

#endif
