#ifndef _TIKTOK_H
#define _TIKTOK_H

/* #define TIKTOK */

#ifdef RELEASE
#ifdef TIKTOK
#undef TIKTOK
#endif
#endif

#ifndef TIKTOK

#define tik(n, s) do { } while (0);
#define tok(n) do { } while (0);

#else

void tik_debug(int n, const char *desc, const char *file, int line, const char *func);
void tok_debug(int n, const char *file, int line, const char *func);

#define tik(n, s) do { tik_debug((n), (s), __FILE__, __LINE__, __func__); } while (0);
#define tok(n) do { tok_debug((n), __FILE__, __LINE__, __func__); } while (0);

#endif
#endif
