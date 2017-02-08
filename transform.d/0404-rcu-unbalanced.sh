#!/bin/sh

# you have to make SURE that this is executed after the balanced replace
echo $1 | grep drbd_state.c || exit 0 # maybe add more later
sed -ie 's/rcu_read_unlock();/rcu_read_unlock(resource->wrcu_flags);/' $1
sed -ie 's/^\srcu_read_lock();/resource->wrcu_flags = rcu_read_lock();/' $1
