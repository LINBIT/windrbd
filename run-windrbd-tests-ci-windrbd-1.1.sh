# you may have to change those settings:
export VMSHED_TEST_TIMEOUT=30m
export DRBD_TESTS_DIR=tests

# may be windrbd-1.1-from-gitlab or windrbd-1.2-from-gitlab
if [ ! "$WINDRBD_VERSION" ] ; then WINDRBD_VERSION=windrbd-1.1-from-gitlab ; fi
export WINDRBD_VERSION
echo "WinDRBD version is $WINDRBD_VERSION ..."

export LINBIT_DOCKER_REGISTRY=nexus.at.linbit.com:5000
export DRBD_TEST_DOCKER_IMAGE=$LINBIT_DOCKER_REGISTRY/drbd9-tests
# accept all 9.X DRBD versions - we have a separate WINDRBD_VERSION
# which we also check and use for provisioning.
export DRBD_VERSION=9.*
export DRBD_UTILS_VERSION=9.0.0.latest-*
export LINBIT_CI_MAX_CPUS=3
# This is too much for my Linux VM:
# export LINBIT_CI_MAX_CPUS=5

# time ./virter/run-test.sh --base-image=windows-server-2019-created-2023 --startvm=250 --torun=add-connect-delete,add-path-multiple-times,connect,diskless,double-promote-diskless,invalid-names,outdate,quorum,quorum-failover-reconnect,rename,resync-after,resync-after-failover-to-dless,resync-initial,split-brain,stress-connect-and-2pc,suspend-io --repeats=3
# This test should always succeed:
# time ./virter/run-test.sh --variant=windows --torun=invalid-names
# Run all tests supported by WinDRBD:
time ./virter/run-test.sh --variant=windows
