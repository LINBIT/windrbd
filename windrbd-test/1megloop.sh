# Note: for this to work there must be no filesystem on backing device.
while true
do
	windrbd-test.exe --drive=K: --gtest_filter=windrbd.do_write_read_whole_disk_by_1meg_requests --force
done
