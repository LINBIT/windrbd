#include "gtest/gtest.h"
#include "Windows.h"
#include "drbd-device.hpp"
#include <string.h>
#include <stdlib.h>

struct params p = {
	drive: "H:",
	expected_size: 52387840
};

HANDLE do_open_device(void)
{
	HANDLE h;
	DWORD err;

	int len = snprintf(NULL, 0, "\\\\.\\%s", p.drive);
	char *fname = (char*)malloc(len+2);
	EXPECT_NE(fname, (void*)0);
	snprintf(fname, len+1, "\\\\.\\%s", p.drive);

	h = CreateFile(fname, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(h, INVALID_HANDLE_VALUE);

	return h;
}

TEST(win_drbd, open_device)
{
	do_open_device();
}

TEST(win_drbd, open_and_close_device)
{
	HANDLE h = do_open_device();
	CloseHandle(h);
}

TEST(win_drbd, get_drive_geometry)
{
	HANDLE h = do_open_device();
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

TEST(win_drbd, get_drive_geometry_invalid)
{
	HANDLE h = do_open_device();
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

TEST(win_drbd, get_drive_geometry_ex)
{
	HANDLE h = do_open_device();
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

TEST(win_drbd, get_partition_information_ex)
{
	HANDLE h = do_open_device();
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

TEST(win_drbd, set_partition_information)
{
	HANDLE h = do_open_device();
	struct _SET_PARTITION_INFORMATION s;
	DWORD size;
	BOOL ret;
	int err;

	size = sizeof(s);
	s.PartitionType = PARTITION_EXTENDED;
	ret = DeviceIoControl(h, IOCTL_DISK_SET_PARTITION_INFO, &s, sizeof(s), NULL, 0, &size, NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);

	CloseHandle(h);
}

TEST(win_drbd, get_length_info)
{
	HANDLE h = do_open_device();
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

TEST(win_drbd, do_read)
{
	HANDLE h = do_open_device();
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

TEST(win_drbd, do_write_read)
{
	HANDLE h = do_open_device();
	DWORD bytes_read, bytes_written;
	BOOL ret;
	int err;
	char buf[512], buf2[512];
	unsigned int i;
	DWORD p;

	for (i=0;i<sizeof(buf);i++)
		buf[i] = i;

	ret = WriteFile(h, buf, sizeof(buf), &bytes_written,  NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);
	EXPECT_EQ(bytes_written, sizeof(buf));

	p = SetFilePointer(h, 0, NULL, FILE_BEGIN);
	EXPECT_EQ(p, 0);
	
	ret = ReadFile(h, buf2, sizeof(buf2), &bytes_read,  NULL);
	err = GetLastError();

	EXPECT_EQ(err, ERROR_SUCCESS);
	EXPECT_NE(ret, 0);
	EXPECT_EQ(bytes_read, sizeof(buf2));

	for (i=0;i<10;i++)
		EXPECT_EQ(buf[i], buf2[i]);

	CloseHandle(h);
}

