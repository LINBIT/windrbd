#!/usr/bin/perl -pi.bak

# -       peer_device = list_first_or_null_rcu(&device->peer_devices,
#-                           struct drbd_peer_device,
#-                           peer_devices);
#+        list_first_or_null_rcu(peer_device, &device->peer_devices, struct drbd_peer_device, peer_devices);


s/^(\s*)(\w+)\s*=\s*(list_first_or_null_rcu\()/$1$3$2, /;
