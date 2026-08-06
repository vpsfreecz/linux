// SPDX-License-Identifier: GPL-2.0
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int signal_ready(const char *path)
{
	static const char ready[] = "ready\n";
	ssize_t n;
	int fd;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		return -1;
	}

	n = write(fd, ready, sizeof(ready) - 1);
	if (n != sizeof(ready) - 1) {
		fprintf(stderr, "%s: readiness write returned %zd\n", path, n);
		close(fd);
		return -1;
	}

	if (close(fd)) {
		perror("close ready");
		return -1;
	}
	return 0;
}

static int wait_for_go(const char *path)
{
	char byte;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		return -1;
	}

	n = read(fd, &byte, sizeof(byte));
	if (n != sizeof(byte)) {
		fprintf(stderr, "%s: go read returned %zd\n", path, n);
		close(fd);
		return -1;
	}

	if (close(fd)) {
		perror("close go");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct dirent *de;
	struct stat st;
	bool found = false;
	DIR *dir;
	int fd;
	int ret = 1;

	if (argc != 6) {
		fprintf(stderr,
			"usage: %s DIRECTORY ENTRY LOOKUP_PATH READY_FIFO GO_FIFO\n",
			argv[0]);
		return 1;
	}

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror("/dev/null");
		return 1;
	}
	if (dup2(fd, 9) < 0) {
		perror("dup2");
		close(fd);
		return 1;
	}
	if (fd != 9)
		close(fd);

	dir = opendir(argv[1]);
	if (!dir) {
		perror(argv[1]);
		return 1;
	}

	if (signal_ready(argv[4]) || wait_for_go(argv[5]))
		goto out;

	errno = 0;
	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, argv[2]))
			found = true;
	}
	if (errno) {
		perror("readdir");
		goto out;
	}

	printf("readdir=%s\n", found ? "present" : "missing");
	if (!lstat(argv[3], &st)) {
		printf("lookup=present\n");
	} else if (errno == ENOENT) {
		printf("lookup=missing\n");
	} else {
		perror(argv[3]);
		goto out;
	}

	ret = 0;
out:
	if (closedir(dir)) {
		perror("closedir");
		ret = 1;
	}
	return ret;
}
