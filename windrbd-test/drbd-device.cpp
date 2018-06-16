#include "gtest/gtest.h"
#include "Windows.h"
#include "drbd-device.hpp"
#include <string.h>
#include <stdlib.h>

struct params p = {
	drive: "H:",
	expected_size: 52387840,
	force: false,
	dump_file: NULL
};

HANDLE do_open_device(int readonly)
{
	HANDLE h;
	DWORD err;

	int len = snprintf(NULL, 0, "\\\\.\\%s", p.drive);
	char *fname = (char*)malloc(len+2);
	EXPECT_NE(fname, (void*)0);
	snprintf(fname, len+1, "\\\\.\\%s", p.drive);

printf("opening file %s\n", fname);

	if (readonly)
		h = CreateFile(fname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	else
		h = CreateFile(fname, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(h, INVALID_HANDLE_VALUE);

	return h;
}

TEST(windrbd, open_device)
{
	do_open_device(0);
}

TEST(windrbd, open_device_readonly)
{
	do_open_device(1);
}

TEST(windrbd, open_and_close_device)
{
	HANDLE h = do_open_device(0);
	CloseHandle(h);
}

TEST(windrbd, get_drive_geometry)
{
	HANDLE h = do_open_device(0);
	struct _DISK_GEOMETRY g;
	DWORD size;
	BOOL ret;
	int err;

	ret = DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &g, sizeof(g), &size, NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);
	EXPECT_EQ(size, sizeof(g));
	EXPECT_EQ(g.BytesPerSector, 512);
	EXPECT_EQ(g.Cylinders.QuadPart, p.expected_size / 512);
	EXPECT_EQ(g.TracksPerCylinder, 1);
	EXPECT_EQ(g.SectorsPerTrack, 1);
	EXPECT_EQ(g.MediaType, FixedMedia);

	CloseHandle(h);
}

TEST(windrbd, get_drive_geometry_invalid)
{
	HANDLE h = do_open_device(0);
	struct _DISK_GEOMETRY g;
	DWORD size;
	BOOL ret;
	int err;

	ret = DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &g, sizeof(g)-1, &size, NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_INSUFFICIENT_BUFFER);
	EXPECT_EQ(ret, 0);

	CloseHandle(h);
}

TEST(windrbd, get_drive_geometry_ex)
{
	HANDLE h = do_open_device(0);
	struct _DISK_GEOMETRY_EX g;
	DWORD size;
	BOOL ret;
	int err;

	ret = DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &g, sizeof(g), &size, NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);
	EXPECT_EQ(size, sizeof(g));
	EXPECT_EQ(g.Geometry.BytesPerSector, 512);
	EXPECT_EQ(g.Geometry.Cylinders.QuadPart, p.expected_size / 512);
	EXPECT_EQ(g.Geometry.TracksPerCylinder, 1);
	EXPECT_EQ(g.Geometry.SectorsPerTrack, 1);
	EXPECT_EQ(g.Geometry.MediaType, FixedMedia);
	EXPECT_EQ(g.DiskSize.QuadPart, p.expected_size);

	CloseHandle(h);
}

TEST(windrbd, get_partition_information_ex)
{
	HANDLE h = do_open_device(0);
	struct _PARTITION_INFORMATION_EX pi;
	DWORD size;
	BOOL ret;
	int err;

	ret = DeviceIoControl(h, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &pi, sizeof(pi), &size, NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);
	EXPECT_EQ(size, sizeof(pi));
	EXPECT_EQ(pi.PartitionStyle, PARTITION_STYLE_MBR);
	EXPECT_EQ(pi.StartingOffset.QuadPart, 0);
	EXPECT_EQ(pi.PartitionLength.QuadPart, p.expected_size);
	EXPECT_EQ(pi.PartitionNumber, 1);

	CloseHandle(h);
}

TEST(windrbd, set_partition_information)
{
	HANDLE h = do_open_device(0);
	struct _SET_PARTITION_INFORMATION s;
	DWORD size;
	BOOL ret;
	int err;

	if (!p.force) {
	        char answer[10];

		fprintf(stderr, "This test might *DESTROY* the partition.\n");
		fprintf(stderr, "Please type y<enter> if you wish to do this.\n");
		fgets(answer, sizeof(answer)-1, stdin);
		if (answer[0] != 'y') {
			fprintf(stderr, "Set partition information test not done.\n");
			return;
		}
	}

	size = sizeof(s);
	s.PartitionType = PARTITION_EXTENDED;
	ret = DeviceIoControl(h, IOCTL_DISK_SET_PARTITION_INFO, &s, sizeof(s), NULL, 0, &size, NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);

	CloseHandle(h);
}

TEST(windrbd, get_length_info)
{
	HANDLE h = do_open_device(0);
	struct _GET_LENGTH_INFORMATION l;
	DWORD size;
	BOOL ret;
	int err;

	ret = DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &l, sizeof(l), &size, NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);
	EXPECT_EQ(size, sizeof(l));
	EXPECT_EQ(l.Length.QuadPart, p.expected_size);

	CloseHandle(h);
}

TEST(windrbd, do_read)
{
	HANDLE h = do_open_device(0);
	DWORD bytes_read;
	BOOL ret;
	int err;
	char buf[512];

	ret = ReadFile(h, buf, sizeof(buf), &bytes_read,  NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);
	EXPECT_EQ(bytes_read, sizeof(buf));

	CloseHandle(h);
}

TEST(windrbd, do_write_read)
{
	HANDLE h = do_open_device(0);
	DWORD bytes_read, bytes_written;
	BOOL ret;
	int err;
	char buf[512], buf2[512];
	unsigned int i;
	DWORD px;

	if (!p.force) {
	        char answer[10];

		fprintf(stderr, "This test will *DESTROY* the first sectors of the underlying backing device.\n");
		fprintf(stderr, "Please type y<enter> if you wish to do this.\n");
		fgets(answer, sizeof(answer)-1, stdin);
		if (answer[0] != 'y') {
			fprintf(stderr, "Write test not done.\n");
			return;
		}
	}

	for (i=0;i<sizeof(buf);i++)
		buf[i] = i;

	ret = WriteFile(h, buf, sizeof(buf), &bytes_written,  NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);
	EXPECT_EQ(bytes_written, sizeof(buf));

	px = SetFilePointer(h, 0, NULL, FILE_BEGIN);
	EXPECT_EQ(px, 0);
	
	ret = ReadFile(h, buf2, sizeof(buf2), &bytes_read,  NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);
	EXPECT_EQ(bytes_read, sizeof(buf2));

	for (i=0;i<10;i++)
		EXPECT_EQ(buf[i], buf2[i]);

	CloseHandle(h);
}

TEST(windrbd, do_write_read_whole_disk_by_1meg_requests)
{
#define ONE_MEG (65536*16)

	HANDLE h = do_open_device(0);
	DWORD bytes_read, bytes_written;
	BOOL ret;
	int err;
	// char buf[ONE_MEG], buf2[ONE_MEG];
	char *buf, *buf2;
	unsigned int i;
	DWORD px;
	unsigned int sector;
	unsigned int sector2;

	if (!p.force) {
	        char answer[10];

		fprintf(stderr, "This test will *DESTROY* the whole data on the disk of the underlying backing device.\n");
		fprintf(stderr, "Please type y<enter> if you wish to do this.\n");
		fgets(answer, sizeof(answer)-1, stdin);
		if (answer[0] != 'y') {
			fprintf(stderr, "Write test not done.\n");
			return;
		}
	}

	buf = (char*)malloc(ONE_MEG);
	if (buf == NULL) {
		printf("Out of memory.\n");
		exit(1);
	}
	buf2 = (char*)malloc(ONE_MEG);
	if (buf2 == NULL) {
		printf("Out of memory.\n");
		exit(1);
	}

	sector2 = 0;
	for (sector=0; sector<p.expected_size / ONE_MEG; sector++) {
		for (i=0;i<ONE_MEG;i++)
			buf[i] = i;
		for (i=0;i<ONE_MEG;i+=512, sector2++)
			*(int*)(buf+i) = sector2;

		printf("Sector is %d\n", sector);

		ret = WriteFile(h, buf, ONE_MEG, &bytes_written,  NULL);
		err = GetLastError();

		EXPECT_EQ(err, ERROR_SUCCESS);
		EXPECT_NE(ret, 0);
		EXPECT_EQ(bytes_written, ONE_MEG);

		px = SetFilePointer(h, ONE_MEG*sector, NULL, FILE_BEGIN);
		EXPECT_EQ(px, ONE_MEG*sector);

		ret = ReadFile(h, buf2, ONE_MEG, &bytes_read,  NULL);
		err = GetLastError();

		EXPECT_EQ(err, ERROR_SUCCESS);
		EXPECT_NE(ret, 0);
		EXPECT_EQ(bytes_read, ONE_MEG);

/*		for (i=0;i<10;i++)
			EXPECT_EQ(buf[i], buf2[i]); */
	}
	free(buf);
	free(buf2);

	CloseHandle(h);
}

TEST(windrbd, do_write_read_whole_disk)
{
	HANDLE h = do_open_device(0);
	DWORD bytes_read, bytes_written;
	BOOL ret;
	int err;
	char buf[512], buf2[512];
	unsigned int i;
	DWORD px;
	unsigned int sector;

	if (!p.force) {
	        char answer[10];

		fprintf(stderr, "This test will *DESTROY* the whole data on the disk of the underlying backing device.\n");
		fprintf(stderr, "Please type y<enter> if you wish to do this.\n");
		fgets(answer, sizeof(answer)-1, stdin);
		if (answer[0] != 'y') {
			fprintf(stderr, "Write test not done.\n");
			return;
		}
	}

	for (sector=0; sector<p.expected_size / 512; sector++) {
		for (i=0;i<sizeof(buf);i++)
			buf[i] = i;
		*(int*)buf = sector;

		printf("Sector is %d\n", sector);

		ret = WriteFile(h, buf, sizeof(buf), &bytes_written,  NULL);
		err = GetLastError();

		EXPECT_EQ(err, ERROR_SUCCESS);
		EXPECT_NE(ret, 0);
		EXPECT_EQ(bytes_written, sizeof(buf));

		px = SetFilePointer(h, 512*sector, NULL, FILE_BEGIN);
		EXPECT_EQ(px, 512*sector);

		ret = ReadFile(h, buf2, sizeof(buf2), &bytes_read,  NULL);
		err = GetLastError();

		EXPECT_EQ(err, ERROR_SUCCESS);
		EXPECT_NE(ret, 0);
		EXPECT_EQ(bytes_read, sizeof(buf2));

/*		for (i=0;i<10;i++)
			EXPECT_EQ(buf[i], buf2[i]); */
	}

	CloseHandle(h);
}

TEST(windrbd, do_read_past_end_of_device)
{
	HANDLE h = do_open_device(0);
	BOOL ret;
	int err;
	char buf[512];
	unsigned int i;
	DWORD px;
	DWORD bytes_written;

	for (i=0;i<sizeof(buf);i++)
		buf[i] = i;

	px = SetFilePointer(h, p.expected_size, NULL, FILE_BEGIN);
	err = GetLastError();
	printf("px is %d err is %d\n", px, err);
	ret = ReadFile(h, buf, sizeof(buf), &bytes_written,  NULL);
	err = GetLastError();
	printf("ret is %d err is %d\n", ret, err);

	CloseHandle(h);
}

TEST(windrbd, copy_disk_to_file)
{
	HANDLE h = do_open_device(0);
	HANDLE f;
	DWORD bytes_read, bytes_written;
	BOOL ret;
	int err;
	char buf[512];
	unsigned int i;
	unsigned int sector;

	if (p.dump_file == NULL) {
		printf("Skipping copy_disk_to_file test, please use --dump-file <fname> to enable this\n");
		return;
	}

	printf("Opening file %s for writing.\n", p.dump_file);

	f = CreateFile(p.dump_file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	err = GetLastError();

	ASSERT_EQ(err, ERROR_SUCCESS);
	ASSERT_NE(f, INVALID_HANDLE_VALUE);

	for (sector=0; sector<p.expected_size / 512; sector++) {
		for (i=0;i<sizeof(buf);i++)
			buf[i] = i;
		*(int*)buf = sector;

		printf("Sector is %d\n", sector);

		ret = ReadFile(h, buf, sizeof(buf), &bytes_read,  NULL);
		err = GetLastError();

		EXPECT_EQ(err, ERROR_SUCCESS);
		EXPECT_NE(ret, 0);
		EXPECT_EQ(bytes_read, sizeof(buf));

		ret = WriteFile(f, buf, sizeof(buf), &bytes_written,  NULL);
		err = GetLastError();

		EXPECT_EQ(err, ERROR_SUCCESS);
		EXPECT_NE(ret, 0);
		EXPECT_EQ(bytes_written, sizeof(buf));
	}

	CloseHandle(h);
	CloseHandle(f);
}

TEST(windrbd, flush_disk)
{
	HANDLE h = do_open_device(0);
	BOOL ret;
	int err;

	ret = FlushFileBuffers(h);
	err = GetLastError();

	EXPECT_NE(ret, 0);
	EXPECT_EQ(err, ERROR_SUCCESS);

	CloseHandle(h);
}

TEST(windrbd, dismount_volume)
{
	HANDLE h = do_open_device(0);
	BOOL ret;
	int err;
	DWORD size;

	ret = DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &size, NULL);
	err = GetLastError();

	EXPECT_NE(ret, 0);
	EXPECT_EQ(err, ERROR_SUCCESS);

	CloseHandle(h);
}

