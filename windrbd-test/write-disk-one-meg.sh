# ./windrbd-test --drive=$1 --gtest_filter=windrbd.do_write_read_whole_disk_by_1meg_requests --expected-size=$2 --request-size=$3 --mode=$4 --force
./windrbd-test --drive=$1 --gtest_filter=windrbd.do_write_read_whole_disk_by_1meg_requests --expected-size=$2 --request-size=$3 --mode=$4 --force --stop-on-error
