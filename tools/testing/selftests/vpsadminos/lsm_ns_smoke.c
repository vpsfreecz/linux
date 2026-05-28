// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_lsm_set_self_attr
#ifdef __alpha__
#define __NR_lsm_set_self_attr 570
#else
#define __NR_lsm_set_self_attr 460
#endif
#endif

#ifndef LSM_ID_APPARMOR
#define LSM_ID_APPARMOR 104
#endif
#ifndef LSM_ID_SELINUX
#define LSM_ID_SELINUX 101
#endif
#ifndef LSM_ATTR_UNSHARE
#define LSM_ATTR_UNSHARE 106
#endif

#ifndef STACK_SIZE
#define STACK_SIZE (1024 * 1024)
#endif

#define KSFT_SKIP 4
#define NS_LINK_SIZE 128

struct lsm_ctx {
	uint64_t id;
	uint64_t flags;
	uint64_t len;
	uint64_t ctx_len;
	unsigned char ctx[];
};

struct child_result {
	int err;
	char user_ns[NS_LINK_SIZE];
	char lsm_ns[NS_LINK_SIZE];
};

struct child_cfg {
	int pipefd;
};

static int read_ns_link(const char *name, char *buf, size_t size)
{
	char path[PATH_MAX];
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
	n = readlink(path, buf, size - 1);
	if (n < 0)
		return -1;

	buf[n] = '\0';
	return 0;
}

static int write_full(int fd, const void *buf, size_t size)
{
	const char *pos = buf;

	while (size) {
		ssize_t ret = write(fd, pos, size);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!ret) {
			errno = EIO;
			return -1;
		}

		pos += ret;
		size -= ret;
	}

	return 0;
}

static int read_full(int fd, void *buf, size_t size)
{
	char *pos = buf;

	while (size) {
		ssize_t ret = read(fd, pos, size);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!ret) {
			errno = EIO;
			return -1;
		}

		pos += ret;
		size -= ret;
	}

	return 0;
}

static int request_lsm_ns(uint64_t lsm_id, const char *name)
{
	struct lsm_ctx *ctx;
	size_t name_len = name ? strlen(name) + 1 : 0;
	size_t size = sizeof(*ctx) + name_len;
	int ret;

	ctx = calloc(1, size);
	if (!ctx)
		return -1;

	ctx->id = lsm_id;
	ctx->len = size;
	ctx->ctx_len = name_len;
	if (name_len)
		memcpy(ctx->ctx, name, name_len);

	ret = syscall(__NR_lsm_set_self_attr, LSM_ATTR_UNSHARE, ctx, size, 0);
	free(ctx);
	return ret;
}

static int child_main(void *arg)
{
	struct child_cfg *cfg = arg;
	struct child_result result = { .err = 0 };

	if (read_ns_link("user", result.user_ns, sizeof(result.user_ns)) ||
	    read_ns_link("lsm", result.lsm_ns, sizeof(result.lsm_ns)))
		result.err = errno ? errno : EIO;

	if (write_full(cfg->pipefd, &result, sizeof(result)) && !result.err)
		result.err = errno ? errno : EIO;
	close(cfg->pipefd);

	return result.err ? 1 : 0;
}

static int clone_child(struct child_result *result)
{
	struct child_cfg cfg;
	char *stack;
	char *stack_top;
	int pipefd[2];
	pid_t pid;
	int status;
	int saved_errno;

	if (pipe(pipefd) < 0)
		return -1;

	stack = malloc(STACK_SIZE);
	if (!stack) {
		close(pipefd[0]);
		close(pipefd[1]);
		errno = ENOMEM;
		return -1;
	}

	cfg.pipefd = pipefd[1];
	stack_top = stack + STACK_SIZE;
	pid = clone(child_main, stack_top, CLONE_NEWUSER | SIGCHLD, &cfg);
	saved_errno = errno;
	close(pipefd[1]);

	if (pid < 0) {
		close(pipefd[0]);
		free(stack);
		errno = saved_errno;
		return -1;
	}

	if (read_full(pipefd[0], result, sizeof(*result))) {
		result->err = errno ? errno : EIO;
		result->user_ns[0] = '\0';
		result->lsm_ns[0] = '\0';
	}
	close(pipefd[0]);

	if (waitpid(pid, &status, 0) < 0) {
		free(stack);
		return -1;
	}

	free(stack);

	if (!WIFEXITED(status)) {
		errno = ECHILD;
		return -1;
	}
	if (WEXITSTATUS(status) || result->err) {
		errno = result->err ? result->err : ECHILD;
		return -1;
	}

	return 0;
}

static int skip_errno(int err)
{
	return err == EOPNOTSUPP || err == EPERM;
}

static int run_lsm_ns_test(int nr, const char *label, uint64_t lsm_id,
			   const char *name, const char *parent_user_ns,
			   const char *parent_lsm_ns)
{
	struct child_result child = { 0 };

	if (request_lsm_ns(lsm_id, name)) {
		if (skip_errno(errno)) {
			printf("ok %d # SKIP cannot arm %s LSM namespace request: %s\n",
			       nr, label, strerror(errno));
			return KSFT_SKIP;
		}

		printf("not ok %d failed to arm %s LSM namespace request\n",
		       nr, label);
		perror("lsm_set_self_attr(LSM_ATTR_UNSHARE)");
		return 1;
	}

	if (clone_child(&child)) {
		if (skip_errno(errno)) {
			printf("ok %d # SKIP cannot create child %s LSM namespace: %s\n",
			       nr, label, strerror(errno));
			return KSFT_SKIP;
		}

		printf("not ok %d failed to create child %s LSM namespace\n",
		       nr, label);
		perror("clone(CLONE_NEWUSER)");
		return 1;
	}

	if (!strcmp(parent_user_ns, child.user_ns)) {
		printf("not ok %d child stayed in parent user namespace\n", nr);
		fprintf(stderr, "child stayed in parent user namespace %s\n",
			parent_user_ns);
		return 1;
	}

	if (!strcmp(parent_lsm_ns, child.lsm_ns)) {
		printf("not ok %d child stayed in parent LSM namespace\n", nr);
		fprintf(stderr, "child stayed in parent LSM namespace %s\n",
			parent_lsm_ns);
		return 1;
	}

	printf("ok %d child user namespace consumed %s LSM namespace request\n",
	       nr, label);
	return 0;
}

int main(void)
{
	char parent_user_ns[NS_LINK_SIZE];
	char parent_lsm_ns[NS_LINK_SIZE];
	int apparmor_ret, selinux_ret;

	if (read_ns_link("lsm", parent_lsm_ns, sizeof(parent_lsm_ns))) {
		printf("TAP version 13\n1..0 # SKIP no lsm namespace file\n");
		return KSFT_SKIP;
	}
	if (read_ns_link("user", parent_user_ns, sizeof(parent_user_ns))) {
		perror("read parent user namespace");
		return 1;
	}

	printf("TAP version 13\n");
	printf("1..2\n");

	apparmor_ret = run_lsm_ns_test(1, "AppArmor", LSM_ID_APPARMOR,
				       "selftest-lsmns", parent_user_ns,
				       parent_lsm_ns);
	selinux_ret = run_lsm_ns_test(2, "SELinux", LSM_ID_SELINUX, NULL,
				      parent_user_ns, parent_lsm_ns);

	if (apparmor_ret == 1 || selinux_ret == 1)
		return 1;
	if (apparmor_ret == KSFT_SKIP && selinux_ret == KSFT_SKIP)
		return KSFT_SKIP;
	return 0;
}
