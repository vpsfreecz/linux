// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
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
	bool nested_attempt;
};

static int do_syslog_action(int type, const char *buf, int len)
{
	return syscall(SYS_syslog, type, buf, len);
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

static int child_main(void *arg)
{
	struct child_cfg *cfg = arg;
	int err = 0;

	if (emit_ns_link(cfg->pipefd, "child_user", "/proc/self/ns/user") ||
	    emit_ns_link(cfg->pipefd, "child_pid", "/proc/self/ns/pid") ||
	    emit_ns_link(cfg->pipefd, "child_syslog", "/proc/self/ns/syslog") ||
	    emit_ns_link(cfg->pipefd, "child_tracing", "/proc/self/ns/tracing")) {
		err = errno;
		dprintf(cfg->pipefd, "child_errno=%d\n", err);
		close(cfg->pipefd);
		return 1;
	}

	if (cfg->nested_attempt) {
		int ret = do_syslog_action(SYSLOG_ACTION_NEW_TRACING_NS, NULL, 0);
		int nested_errno = ret < 0 ? errno : 0;
		dprintf(cfg->pipefd, "child_nested_tracing_errno=%d\n", nested_errno);
	}

	close(cfg->pipefd);
	return 0;
}

int main(int argc, char **argv)
{
	bool arm_syslog = false;
	bool arm_tracing = false;
	bool nested_attempt = false;
	const char *syslog_name = NULL;
	char *stack;
	int pipefd[2];
	struct child_cfg cfg;
	pid_t pid;
	int status;
	char buf[4096];
	ssize_t nr;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--syslog-name")) {
			if (i + 1 >= argc) {
				fprintf(stderr, "missing argument for --syslog-name\n");
				return 2;
			}
			arm_syslog = true;
			syslog_name = argv[++i];
		} else if (!strcmp(argv[i], "--tracing")) {
			arm_tracing = true;
		} else if (!strcmp(argv[i], "--nested-attempt")) {
			nested_attempt = true;
		} else {
			fprintf(stderr, "unknown argument: %s\n", argv[i]);
			return 2;
		}
	}

	if (emit_ns_link(STDOUT_FILENO, "parent_user", "/proc/self/ns/user") ||
	    emit_ns_link(STDOUT_FILENO, "parent_pid", "/proc/self/ns/pid") ||
	    emit_ns_link(STDOUT_FILENO, "parent_syslog", "/proc/self/ns/syslog") ||
	    emit_ns_link(STDOUT_FILENO, "parent_tracing", "/proc/self/ns/tracing")) {
		perror("readlink");
		return 1;
	}

	if (arm_syslog) {
		if (do_syslog_action(SYSLOG_ACTION_NEW_NS, syslog_name,
				     strlen(syslog_name)) < 0) {
			perror("SYSLOG_ACTION_NEW_NS");
			return 1;
		}
	}

	if (arm_tracing) {
		if (do_syslog_action(SYSLOG_ACTION_NEW_TRACING_NS, NULL, 0) < 0) {
			perror("SYSLOG_ACTION_NEW_TRACING_NS");
			return 1;
		}
	}

	if (pipe(pipefd) < 0) {
		perror("pipe");
		return 1;
	}

	stack = malloc(STACK_SIZE);
	if (!stack) {
		perror("malloc");
		return 1;
	}

	cfg.pipefd = pipefd[1];
	cfg.nested_attempt = nested_attempt;

	pid = clone(child_main, stack + STACK_SIZE,
		    SIGCHLD | CLONE_NEWUSER | CLONE_NEWPID, &cfg);
	if (pid < 0) {
		dprintf(STDOUT_FILENO, "clone_errno=%d\n", errno);
		close(pipefd[0]);
		close(pipefd[1]);
		free(stack);
		return 0;
	}

	close(pipefd[1]);
	while ((nr = read(pipefd[0], buf, sizeof(buf))) > 0) {
		if (write(STDOUT_FILENO, buf, nr) != nr) {
			perror("write");
			close(pipefd[0]);
			free(stack);
			return 1;
		}
	}
	close(pipefd[0]);

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
