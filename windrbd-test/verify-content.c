#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char ** argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <device>\n", argv[0]);
		fprintf(stderr, "Intended to be run on a Linux host to verify if synced data matches\nthe expected value (written by tests do_write_read_whole_disk_by_1meg_requests\nor do_write_read_whole_disk).\n");

		return 1;
	}
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	char buf[512];
	int sector = 0;
	int i;
	int ret;

	while ((ret=read(fd, buf, 512)) == 512) {
		if (*(int*)buf != sector) {
			printf("sector mismatch: is %d expected %d.\n", *(int*)buf, sector);
		}
		sector++;
		for (i=4;i<512;i++) {
			if (buf[i] != (char)i)
				printf("data mismatch in sector %d: is %d expected %d.\n", sector, buf[i], i);
		}
	}
	if (ret < 0) {
		perror("read");
		return 1;
	}
	if (ret != 0) {
		printf("Warning: size not a multiple of 512.\n");
	}
	close(fd);
}



