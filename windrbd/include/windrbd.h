#ifndef WINDRBD_H
#define WINDRBD_H

struct drbd_device;

int windrbd_become_primary(struct drbd_device *device, const char **err_str);
int windrbd_become_secondary(struct drbd_device *device, const char **err_str);

#endif
