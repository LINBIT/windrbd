#ifndef _TIKTOK_H
#define _TIKTOK_H

void tik_debug(const char *file, int line, const char *func);
void tok_debug(const char *file, int line, const char *func);

#define tik() do { tik_debug(__FILE__, __LINE__, __func__); } while (0);
#define tok() do { tok_debug(__FILE__, __LINE__, __func__); } while (0);

#endif
