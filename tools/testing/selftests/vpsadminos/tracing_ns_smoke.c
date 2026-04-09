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
	bool setns_parent_tracing;
	const char *nested_syslog_name;
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

static int emit_ns_links(int fd, const char *prefix)
{
	char key[64];
	char path[PATH_MAX];
	const char *names[] = { "user", "pid", "syslog", "tracing" };
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		snprintf(key, sizeof(key), "%s_%s", prefix, names[i]);
		snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
		if (emit_ns_link(fd, key, path))
			return -1;
	}

	return 0;
}

static int nested_child_main(void *arg)
{
	struct child_cfg *cfg = arg;
	int err = 0;

	if (emit_ns_links(cfg->pipefd, "grandchild")) {
		err = errno;
		dprintf(cfg->pipefd, "grandchild_errno=%d\n", err);
		close(cfg->pipefd);
		return 1;
	}

	close(cfg->pipefd);
	return 0;
}

static int maybe_run_nested_syslog_child(struct child_cfg *cfg)
{
	char *stack;
	pid_t pid;
	int status;

	if (!cfg->nested_syslog_name)
		return 0;

	if (do_syslog_action(SYSLOG_ACTION_NEW_NS, cfg->nested_syslog_name,
			     strlen(cfg->nested_syslog_name)) < 0) {
		dprintf(cfg->pipefd, "child_nested_syslog_errno=%d\n", errno);
		return 1;
	}

	stack = malloc(STACK_SIZE);
	if (!stack) {
		dprintf(cfg->pipefd, "child_nested_syslog_errno=%d\n", errno);
		return 1;
	}

	pid = clone(nested_child_main, stack + STACK_SIZE,
		    SIGCHLD | CLONE_NEWUSER | CLONE_NEWPID, cfg);
	if (pid < 0) {
		dprintf(cfg->pipefd, "child_nested_clone_errno=%d\n", errno);
		free(stack);
		return 1;
	}

	if (waitpid(pid, &status, 0) < 0) {
		dprintf(cfg->pipefd, "child_nested_wait_errno=%d\n", errno);
		free(stack);
		return 1;
	}

	free(stack);
	if (!WIFEXITED(status)) {
		dprintf(cfg->pipefd, "child_nested_wait_errno=%d\n", ECHILD);
		return 1;
	}

	return WEXITSTATUS(status);
}

static int child_main(void *arg)
{
	struct child_cfg *cfg = arg;
	int err = 0;

	if (emit_ns_links(cfg->pipefd, "child")) {
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

	if (cfg->setns_parent_tracing) {
		char path[PATH_MAX];
		int fd;
		int ret;
		int setns_errno;

		snprintf(path, sizeof(path), "/proc/%d/ns/tracing", getppid());
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			dprintf(cfg->pipefd, "child_setns_parent_tracing_errno=%d\n", errno);
		} else {
			ret = setns(fd, 0);
			setns_errno = ret < 0 ? errno : 0;
			dprintf(cfg->pipefd, "child_setns_parent_tracing_errno=%d\n",
				setns_errno);
			close(fd);
		}
	}

	if (maybe_run_nested_syslog_child(cfg)) {
		close(cfg->pipefd);
		return 1;
	}

	close(cfg->pipefd);
	return 0;
}

int main(int argc, char **argv)
{
	bool arm_syslog = false;
	bool arm_tracing = false;
	bool nested_attempt = false;
	bool setns_parent_tracing = false;
	const char *syslog_name = NULL;
	const char *nested_syslog_name = NULL;
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
		} else if (!strcmp(argv[i], "--setns-parent-tracing")) {
			setns_parent_tracing = true;
		} else if (!strcmp(argv[i], "--nested-syslog-name")) {
			if (i + 1 >= argc) {
				fprintf(stderr, "missing argument for --nested-syslog-name\n");
				return 2;
			}
			nested_syslog_name = argv[++i];
		} else {
			fprintf(stderr, "unknown argument: %s\n", argv[i]);
			return 2;
		}
	}

	if (emit_ns_links(STDOUT_FILENO, "parent")) {
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
	cfg.setns_parent_tracing = setns_parent_tracing;
	cfg.nested_syslog_name = nested_syslog_name;

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
