i=0
while true
do
	i=$[ $i + 1 ]
	echo "1 meg I/O $i"
	./windrbd-test.exe --gtest_filter=windrbd.do_write_read_whole_disk_by_1meg_requests --drive=K: --force >/dev/null 2>&1 
done 
