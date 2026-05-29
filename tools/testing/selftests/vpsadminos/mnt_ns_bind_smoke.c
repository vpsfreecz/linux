// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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

static int get_mnt_ns_id(uint64_t *id)
{
	int fd;

	fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror("open mount namespace");
		return -1;
	}

	if (ioctl(fd, NS_GET_MNTNS_ID, id) < 0) {
		perror("NS_GET_MNTNS_ID");
		close(fd);
		return -1;
	}

	close(fd);
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
	if (command != 'x' && command != 'q') {
		fprintf(stderr, "unknown helper command: %c\n", command);
		return 1;
	}

	if (command == 'x') {
		snprintf(src, sizeof(src), "/proc/%ld/ns/mnt", (long)parent);
		snprintf(dst, sizeof(dst), "%s/parent.mnt", dir);

		fd = open(dst, O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_RDONLY,
			  0600);
		if (fd < 0) {
			err = errno;
		} else {
			close(fd);

			if (mount(src, dst, NULL, MS_BIND, NULL) < 0)
				err = errno;
			else
				(void)umount2(dst, MNT_DETACH);
		}
	}

	if (write_full(result_fd, &err, sizeof(err)) < 0) {
		perror("helper write result");
		return 1;
	}

	if (command == 'x')
		(void)unlink(dst);
	return 0;
}

static int wait_helper(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) != child) {
		perror("waitpid");
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "helper exited abnormally: status=%d\n", status);
		return -1;
	}

	return 0;
}

int main(void)
{
	char tmpdir[] = "/tmp/vpsadminos-mntns-bind-XXXXXX";
	const int max_attempts = 8;
	int low_cpu, high_cpu, cpu_count;
	int command_pipe[2], result_pipe[2];
	int current_cpu, mount_errno;
	uint64_t old_id, new_id;
	pid_t parent, child;
	char command;

	cpu_count = choose_cpus(&low_cpu, &high_cpu);
	if (cpu_count < 0)
		return 1;

	if (cpu_count < 2) {
		printf("ok - skipped, cross-CPU namespace probe needs two CPUs\n");
		return 0;
	}

	if (!mkdtemp(tmpdir)) {
		perror("mkdtemp");
		return 1;
	}

	current_cpu = low_cpu;
	if (pin_cpu(current_cpu) < 0)
		return 1;

	if (unshare(CLONE_NEWNS) < 0) {
		perror("unshare initial mount namespace");
		return 1;
	}
	if (get_mnt_ns_id(&old_id) < 0)
		return 1;

	parent = getpid();

	for (int attempt = 0; attempt < max_attempts; attempt++) {
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
			return helper_main(command_pipe[0], result_pipe[1],
					   parent, tmpdir);
		}

		close(command_pipe[0]);
		close(result_pipe[1]);

		current_cpu = current_cpu == low_cpu ? high_cpu : low_cpu;
		if (pin_cpu(current_cpu) < 0)
			return 1;

		if (unshare(CLONE_NEWNS) < 0) {
			perror("unshare newer mount namespace");
			return 1;
		}
		if (get_mnt_ns_id(&new_id) < 0)
			return 1;

		command = old_id > new_id ? 'x' : 'q';
		if (write_full(command_pipe[1], &command, sizeof(command)) < 0) {
			perror("write command");
			return 1;
		}
		close(command_pipe[1]);

		if (read_full(result_pipe[0], &mount_errno,
			      sizeof(mount_errno)) < 0) {
			perror("read result");
			return 1;
		}
		close(result_pipe[0]);

		if (wait_helper(child) < 0)
			return 1;

		if (old_id > new_id) {
			if (mount_errno != 0) {
				fprintf(stderr,
					"bind of newer namespace %llu from older namespace %llu failed: %s\n",
					(unsigned long long)new_id,
					(unsigned long long)old_id,
					strerror(mount_errno));
				return 1;
			}

			(void)rmdir(tmpdir);
			printf("ok - bound newer %llu from older %llu with inverted IDs\n",
			       (unsigned long long)new_id,
			       (unsigned long long)old_id);
			return 0;
		}

		old_id = new_id;
	}

	(void)rmdir(tmpdir);
	fprintf(stderr,
		"failed to construct an older-ID/newer-ID inversion after %d attempts\n",
		max_attempts);
	return 1;
}
