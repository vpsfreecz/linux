// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int choose_cpus(int *low_cpu, int *high_cpu)
{
	cpu_set_t set;
	int count = 0;

	if (sched_getaffinity(0, sizeof(set), &set) < 0) {
		perror("sched_getaffinity");
		return -1;
	}

	*low_cpu = -1;
	*high_cpu = -1;

	for (int i = 0; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, &set))
			continue;

		if (*low_cpu < 0)
			*low_cpu = i;
		*high_cpu = i;
		count++;
	}

	return count;
}

static int pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);

	if (sched_setaffinity(0, sizeof(set), &set) < 0) {
		perror("sched_setaffinity");
		return -1;
	}

	return 0;
}

static int write_full(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len > 0) {
		ssize_t ret = write(fd, p, len);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		p += ret;
		len -= ret;
	}

	return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
	char *p = buf;

	while (len > 0) {
		ssize_t ret = read(fd, p, len);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EPIPE;
			return -1;
		}

		p += ret;
		len -= ret;
	}

	return 0;
}

static int helper_main(int command_fd, int result_fd, pid_t parent,
		       const char *dir)
{
	char command;
	char src[128];
	char dst[256];
	int err = 0;
	int fd;

	if (read_full(command_fd, &command, sizeof(command)) < 0) {
		perror("helper read command");
		return 1;
	}

	snprintf(src, sizeof(src), "/proc/%ld/ns/mnt", (long)parent);
	snprintf(dst, sizeof(dst), "%s/parent.mnt", dir);

	fd = open(dst, O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_RDONLY, 0600);
	if (fd < 0) {
		err = errno;
	} else {
		close(fd);

		if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
			err = errno;
		} else {
			(void)umount2(dst, MNT_DETACH);
		}
	}

	if (write_full(result_fd, &err, sizeof(err)) < 0) {
		perror("helper write result");
		return 1;
	}

	(void)unlink(dst);
	(void)rmdir(dir);
	return 0;
}

int main(void)
{
	char tmpdir[] = "/tmp/vpsadminos-mntns-bind-XXXXXX";
	int low_cpu, high_cpu, cpu_count;
	int command_pipe[2], result_pipe[2];
	int child_status, mount_errno;
	pid_t parent, child;
	char command = 'x';

	cpu_count = choose_cpus(&low_cpu, &high_cpu);
	if (cpu_count < 0)
		return 1;

	if (cpu_count < 2) {
		printf("ok - skipped, need at least two CPUs for cross-CPU namespace cookie probe\n");
		return 0;
	}

	if (!mkdtemp(tmpdir)) {
		perror("mkdtemp");
		return 1;
	}

	if (pin_cpu(high_cpu) < 0)
		return 1;

	if (unshare(CLONE_NEWNS) < 0) {
		perror("unshare source mount namespace");
		return 1;
	}

	parent = getpid();

	if (pipe2(command_pipe, O_CLOEXEC) < 0) {
		perror("pipe2 command");
		return 1;
	}

	if (pipe2(result_pipe, O_CLOEXEC) < 0) {
		perror("pipe2 result");
		return 1;
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}

	if (child == 0) {
		close(command_pipe[1]);
		close(result_pipe[0]);
		return helper_main(command_pipe[0], result_pipe[1], parent,
				   tmpdir);
	}

	close(command_pipe[0]);
	close(result_pipe[1]);

	if (pin_cpu(low_cpu) < 0)
		return 1;

	if (unshare(CLONE_NEWNS) < 0) {
		perror("unshare target mount namespace");
		return 1;
	}

	if (write_full(command_pipe[1], &command, sizeof(command)) < 0) {
		perror("write command");
		return 1;
	}
	close(command_pipe[1]);

	if (read_full(result_pipe[0], &mount_errno, sizeof(mount_errno)) < 0) {
		perror("read result");
		return 1;
	}
	close(result_pipe[0]);

	if (waitpid(child, &child_status, 0) != child) {
		perror("waitpid");
		return 1;
	}

	if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
		fprintf(stderr, "helper exited abnormally: status=%d\n",
			child_status);
		return 1;
	}

	if (mount_errno != 0) {
		fprintf(stderr,
			"bind mount of newer mount namespace from older helper failed: %s\n",
			strerror(mount_errno));
		return 1;
	}

	printf("ok - bind-mounted newer mount namespace from older helper namespace\n");
	return 0;
}
