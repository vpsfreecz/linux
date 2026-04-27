// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYSLOG_ACTION_NEW_NS
#define SYSLOG_ACTION_NEW_NS 11
#endif
#ifndef SYSLOG_ACTION_NEW_TRACING_NS
#define SYSLOG_ACTION_NEW_TRACING_NS 12
#endif

#ifndef STACK_SIZE
#define STACK_SIZE (1024 * 1024)
#endif

struct child_cfg {
	int pipefd;
	int syncfd;
	const char *symbol;
};

static int do_syslog_action(int type, const char *buf, int len)
{
	return syscall(SYS_syslog, type, buf, len);
}

static int do_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(SYS_bpf, cmd, attr, size);
}

static int emit_ns_link(int fd, const char *key, const char *path)
{
	char link[PATH_MAX];
	ssize_t n;
	int len;

	n = readlink(path, link, sizeof(link) - 1);
	if (n < 0)
		return -1;
	link[n] = '\0';
	len = dprintf(fd, "%s=%s\n", key, link);
	return len < 0 ? -1 : 0;
}

static int emit_ns_links(int fd, const char *prefix)
{
	char key[64];
	char path[PATH_MAX];
	const char *names[] = { "user", "tracing" };
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		snprintf(key, sizeof(key), "%s_%s", prefix, names[i]);
		snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
		if (emit_ns_link(fd, key, path))
			return -1;
	}

	return 0;
}

static int kallsyms_has_symbol(const char *symbol)
{
	FILE *fp;
	char line[512];
	char sym[256];
	char type;
	unsigned long long addr;

	fp = fopen("/proc/kallsyms", "r");
	if (!fp)
		return -errno;

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%llx %c %255s", &addr, &type, sym) != 3)
			continue;
		if (!strcmp(sym, symbol)) {
			fclose(fp);
			return 1;
		}
	}

	fclose(fp);
	return 0;
}

static int create_array_map_errno(void)
{
	union bpf_attr attr = {
		.map_type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(uint32_t),
		.value_size = sizeof(uint64_t),
		.max_entries = 1,
	};
	int fd;

	fd = do_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int write_file(const char *path, const char *buf)
{
	int fd;
	size_t len = strlen(buf);
	ssize_t ret;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	ret = write(fd, buf, len);
	close(fd);
	if (ret != (ssize_t)len)
		return -1;

	return 0;
}

static int map_child_userns(pid_t pid)
{
	char path[PATH_MAX];
	char map[64];
	uid_t uid = getuid();
	gid_t gid = getgid();

	snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
	if (write_file(path, "deny") < 0 && errno != ENOENT)
		return errno;

	snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
	snprintf(map, sizeof(map), "0 %u 1\n", uid);
	if (write_file(path, map) < 0)
		return errno;

	snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
	snprintf(map, sizeof(map), "0 %u 1\n", gid);
	if (write_file(path, map) < 0)
		return errno;

	return 0;
}

static int wait_for_parent_mapping(int fd)
{
	char c;
	ssize_t n;

	n = read(fd, &c, 1);
	close(fd);
	if (n != 1)
		return n < 0 ? errno : EIO;

	return 0;
}

static int enter_nested_userns_root(void)
{
	char path[PATH_MAX];
	char map[64];
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER) < 0)
		return errno;

	snprintf(path, sizeof(path), "/proc/self/setgroups");
	if (write_file(path, "deny") < 0 && errno != ENOENT)
		return errno;

	snprintf(path, sizeof(path), "/proc/self/uid_map");
	snprintf(map, sizeof(map), "0 %u 1\n", uid);
	if (write_file(path, map) < 0)
		return errno;

	snprintf(path, sizeof(path), "/proc/self/gid_map");
	snprintf(map, sizeof(map), "0 %u 1\n", gid);
	if (write_file(path, map) < 0)
		return errno;

	if (setresgid(0, 0, 0) < 0)
		return errno;
	if (setresuid(0, 0, 0) < 0)
		return errno;

	return 0;
}

static int child_main(void *arg)
{
	struct child_cfg *cfg = arg;
	int err;

	err = wait_for_parent_mapping(cfg->syncfd);
	if (err) {
		dprintf(cfg->pipefd, "child_sync_errno=%d\n", err);
		close(cfg->pipefd);
		return 1;
	}

	if (emit_ns_links(cfg->pipefd, "child")) {
		err = errno;
		dprintf(cfg->pipefd, "child_errno=%d\n", err);
		close(cfg->pipefd);
		return 1;
	}

	err = kallsyms_has_symbol(cfg->symbol);
	dprintf(cfg->pipefd, "child_kallsyms_has_symbol=%d\n", err);

	err = create_array_map_errno();
	dprintf(cfg->pipefd, "first_level_bpf_errno=%d\n", err);

	err = enter_nested_userns_root();
	dprintf(cfg->pipefd, "nested_userns_errno=%d\n", err);
	if (err) {
		close(cfg->pipefd);
		return 1;
	}

	if (emit_ns_links(cfg->pipefd, "nested")) {
		err = errno;
		dprintf(cfg->pipefd, "nested_errno=%d\n", err);
		close(cfg->pipefd);
		return 1;
	}

	err = kallsyms_has_symbol(cfg->symbol);
	dprintf(cfg->pipefd, "nested_kallsyms_has_symbol=%d\n", err);

	err = create_array_map_errno();
	dprintf(cfg->pipefd, "nested_bpf_errno=%d\n", err);
	close(cfg->pipefd);
	return 0;
}

int main(int argc, char **argv)
{
	struct child_cfg cfg = { .pipefd = -1 };
	const char *syslog_name = "traceBpf";
	const char *symbol = "copy_process";
	char *stack;
	int pipefd[2];
	int syncfd[2];
	pid_t pid;
	int status;
	char buf[4096];
	ssize_t n;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--syslog-name")) {
			if (++i >= argc) {
				fprintf(stderr, "missing argument for --syslog-name\n");
				return 2;
			}
			syslog_name = argv[i];
		} else if (!strcmp(argv[i], "--symbol")) {
			if (++i >= argc) {
				fprintf(stderr, "missing argument for --symbol\n");
				return 2;
			}
			symbol = argv[i];
		} else {
			fprintf(stderr, "unknown argument: %s\n", argv[i]);
			return 2;
		}
	}

	cfg.symbol = symbol;
	i = kallsyms_has_symbol(symbol);
	if (i < 0) {
		fprintf(stderr, "kallsyms probe failed: %d\n", -i);
		return 1;
	}
	printf("parent_kallsyms_has_symbol=%d\n", i);

	if (emit_ns_links(STDOUT_FILENO, "parent")) {
		perror("emit parent ns links");
		return 1;
	}

	if (do_syslog_action(SYSLOG_ACTION_NEW_NS, syslog_name,
			     strlen(syslog_name)) < 0) {
		perror("SYSLOG_ACTION_NEW_NS");
		return 1;
	}
	if (do_syslog_action(SYSLOG_ACTION_NEW_TRACING_NS, NULL, 0) < 0) {
		perror("SYSLOG_ACTION_NEW_TRACING_NS");
		return 1;
	}

	if (pipe(pipefd) < 0) {
		perror("pipe");
		return 1;
	}
	if (pipe(syncfd) < 0) {
		perror("sync pipe");
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	cfg.pipefd = pipefd[1];
	cfg.syncfd = syncfd[0];
	stack = malloc(STACK_SIZE);
	if (!stack) {
		perror("malloc");
		close(pipefd[0]);
		close(pipefd[1]);
		close(syncfd[0]);
		close(syncfd[1]);
		return 1;
	}

	pid = clone(child_main, stack + STACK_SIZE,
		    SIGCHLD | CLONE_NEWUSER | CLONE_NEWPID, &cfg);
	if (pid < 0) {
		printf("clone_errno=%d\n", errno);
		close(pipefd[0]);
		close(pipefd[1]);
		close(syncfd[0]);
		close(syncfd[1]);
		free(stack);
		return 1;
	}

	close(pipefd[1]);
	close(syncfd[0]);
	i = map_child_userns(pid);
	if (i) {
		printf("map_child_errno=%d\n", i);
		close(syncfd[1]);
		close(pipefd[0]);
		waitpid(pid, &status, 0);
		free(stack);
		return 1;
	}
	if (write(syncfd[1], "x", 1) != 1) {
		perror("sync write");
		close(syncfd[1]);
		close(pipefd[0]);
		waitpid(pid, &status, 0);
		free(stack);
		return 1;
	}
	close(syncfd[1]);

	for (n = 0; n < (ssize_t)sizeof(buf) - 1;) {
		ssize_t r;

		r = read(pipefd[0], buf + n, sizeof(buf) - 1 - n);
		if (r < 0) {
			n = -1;
			break;
		}
		if (r == 0)
			break;
		n += r;
	}
	if (n < 0) {
		perror("read");
		close(pipefd[0]);
		free(stack);
		return 1;
	}
	buf[n] = '\0';
	close(pipefd[0]);
	printf("%s", buf);

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		free(stack);
		return 1;
	}

	free(stack);
	if (!WIFEXITED(status))
		return 1;

	return WEXITSTATUS(status);
}
