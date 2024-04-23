#ifndef _LINUX_UMH_H
#define _LINUX_UMH_H

#define UMH_WAIT_PROC 1

extern int call_usermodehelper(const char *path, char **argv, char **envp, int wait);

#endif
