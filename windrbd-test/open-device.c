#include <windows.h>
#include <stdio.h>

#define	READ_WRITE 0
#define READ_ONLY  1
#define DIRECT     2

HANDLE do_open_device(char *drive, int open_mode)
{
	HANDLE h;
	DWORD err;

	int len = snprintf(NULL, 0, "\\\\.\\%s", drive);
	char *fname = (char*)malloc(len+2);
	snprintf(fname, len+1, "\\\\.\\%s", drive);

printf("opening file %s, mode is %d\n", fname, open_mode);

	switch (open_mode) {
	case READ_ONLY:
		h = CreateFile(fname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		break;

	case READ_WRITE:
		h = CreateFile(fname, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		break;

	case DIRECT:
		h = CreateFile(fname, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED, NULL);
		break;
	}

	err = GetLastError();
	printf("handle is %p err is %d\n", h, err);

	return h;
}

int main(int argc, char ** argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s bdev-name\n", argv[0]);
		fprintf(stderr, "Examples are: F: or Drbd1008\n");
		return 1;
	}
	do_open_device(argv[1], READ_WRITE);
	printf("Device opened, press enter to quit process...\n");
	getchar();
}
