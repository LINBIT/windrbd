/* THIS IS A BAD NAME.
 * A "long" on windows is 32bit, even on 64bit architectures;
 * but WDRBD is really using a "ULONG_PTR" in most places,
 * which is pointer-sized.
 *
 * But renaming that to BITS_PER_ULONG_PTR isn't nice either;
 * guess we'll just have to live with that.
 *
 * TODO: review DRBD code for usage of this.
 * */
#ifndef BITS_PER_LONG
#if defined(_WIN64)
# define BITS_PER_LONG 64
#elif defined(_WIN32)
# define BITS_PER_LONG 32
#else
# define BITS_PER_LONG __WORDSIZE
#endif
#endif

