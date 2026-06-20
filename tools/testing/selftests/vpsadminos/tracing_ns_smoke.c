// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
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
#ifndef __NR_pidfd_open
#define __NR_pidfd_open SYS_pidfd_open
#endif

#ifndef STACK_SIZE
#define STACK_SIZE (1024 * 1024)
#endif

struct child_cfg {
	int pipefd;
	int startfd;
	int readyfd;
	int releasefd;
	pid_t parent_pid;
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

static int write_file(const char *path, const char *buf)
{
	size_t len = strlen(buf);
	ssize_t written;
	int fd, err = 0;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return errno;

	written = write(fd, buf, len);
	if (written != (ssize_t)len)
		err = errno ? errno : EIO;

	close(fd);
	return err;
}

static int write_child_id_map(pid_t pid, const char *name, uid_t id)
{
	char path[PATH_MAX];
	char buf[64];

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
	snprintf(buf, sizeof(buf), "0 %u 1\n", id);
	return write_file(path, buf);
}

static int setup_child_idmaps(pid_t pid)
{
	char path[PATH_MAX];
	int err;

	snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
	err = write_file(path, "deny\n");
	if (err && err != ENOENT)
		return err;

	err = write_child_id_map(pid, "uid_map", getuid());
	if (err)
		return err;

	return write_child_id_map(pid, "gid_map", getgid());
}

static int drop_cap_sys_admin(void)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {};
	unsigned int idx = CAP_SYS_ADMIN / 32;
	__u32 mask = 1U << (CAP_SYS_ADMIN % 32);

	if (syscall(SYS_capget, &hdr, data) < 0)
		return errno;

	data[idx].effective &= ~mask;
	data[idx].permitted &= ~mask;
	data[idx].inheritable &= ~mask;

	if (syscall(SYS_capset, &hdr, data) < 0)
		return errno;

	return 0;
}

static void maybe_hold_for_parent_probe(struct child_cfg *cfg)
{
	char byte;

	if (cfg->readyfd < 0 || cfg->releasefd < 0)
		return;

	if (write(cfg->readyfd, "R", 1) < 0)
		;
	close(cfg->readyfd);

	while (read(cfg->releasefd, &byte, 1) < 0 && errno == EINTR)
		;
	close(cfg->releasefd);
}

static int probe_ns_setns_errno(pid_t pid, const char *ns_name, int nstype)
{
	int pipefd[2];
	pid_t probe;
	int status;
	int err = 0;
	char path[PATH_MAX];

	if (pipe(pipefd) < 0)
		return errno;

	probe = fork();
	if (probe < 0) {
		err = errno;
		close(pipefd[0]);
		close(pipefd[1]);
		return err;
	}

	if (probe == 0) {
		int fd, ret, setns_errno = 0;

		close(pipefd[0]);
		snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, ns_name);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			setns_errno = errno;
		} else {
			ret = setns(fd, nstype);
			setns_errno = ret < 0 ? errno : 0;
			close(fd);
		}
		if (write(pipefd[1], &setns_errno, sizeof(setns_errno)) != sizeof(setns_errno))
			;
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);
	if (read(pipefd[0], &err, sizeof(err)) != sizeof(err))
		err = EIO;
	close(pipefd[0]);

	if (waitpid(probe, &status, 0) < 0)
		return errno;

	if (!WIFEXITED(status)) {
		err = ECHILD;
		return err;
	}

	return err;
}

static int probe_userns_setns_errno(pid_t pid)
{
	return probe_ns_setns_errno(pid, "user", CLONE_NEWUSER);
}

static int probe_pidns_setns_errno(pid_t pid)
{
	return probe_ns_setns_errno(pid, "pid", CLONE_NEWPID);
}

static int probe_syslogns_setns_errno(pid_t pid)
{
	return probe_ns_setns_errno(pid, "syslog", 0);
}

static int probe_pidfd_setns_errno(pid_t pid)
{
	int pipefd[2];
	pid_t probe;
	int status;
	int err = 0;

	if (pipe(pipefd) < 0)
		return errno;

	probe = fork();
	if (probe < 0) {
		err = errno;
		close(pipefd[0]);
		close(pipefd[1]);
		return err;
	}

	if (probe == 0) {
		int fd, ret, setns_errno = 0;

		close(pipefd[0]);
		fd = syscall(__NR_pidfd_open, pid, 0);
		if (fd < 0) {
			setns_errno = errno;
		} else {
			ret = setns(fd, CLONE_NEWUSER | CLONE_NEWPID);
			setns_errno = ret < 0 ? errno : 0;
			close(fd);
		}
		if (write(pipefd[1], &setns_errno, sizeof(setns_errno)) != sizeof(setns_errno))
			;
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);
	if (read(pipefd[0], &err, sizeof(err)) != sizeof(err))
		err = EIO;
	close(pipefd[0]);

	if (waitpid(probe, &status, 0) < 0)
		return errno;

	if (!WIFEXITED(status)) {
		err = ECHILD;
		return err;
	}

	return err;
}

static int probe_pidfd_setns_without_source_cap_errno(pid_t pid)
{
	int pipefd[2];
	pid_t probe;
	int status;
	int err = 0;

	if (pipe(pipefd) < 0)
		return errno;

	probe = fork();
	if (probe < 0) {
		err = errno;
		close(pipefd[0]);
		close(pipefd[1]);
		return err;
	}

	if (probe == 0) {
		int fd, ret, setns_errno = 0;

		close(pipefd[0]);
		setns_errno = drop_cap_sys_admin();

		if (!setns_errno) {
			fd = syscall(__NR_pidfd_open, pid, 0);
			if (fd < 0) {
				setns_errno = errno;
			} else {
				ret = setns(fd, CLONE_NEWUSER | CLONE_NEWPID);
				setns_errno = ret < 0 ? errno : 0;
				close(fd);
			}
		}

		if (write(pipefd[1], &setns_errno, sizeof(setns_errno)) != sizeof(setns_errno))
			;
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);
	if (read(pipefd[0], &err, sizeof(err)) != sizeof(err))
		err = EIO;
	close(pipefd[0]);

	if (waitpid(probe, &status, 0) < 0)
		return errno;

	if (!WIFEXITED(status))
		return ECHILD;

	return err;
}

static int noop_child_main(void *arg)
{
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
	char byte;
	int err = 0;

	while (read(cfg->startfd, &byte, 1) < 0 && errno == EINTR)
		;
	close(cfg->startfd);

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

		snprintf(path, sizeof(path), "/proc/%d/ns/tracing",
			 cfg->parent_pid);
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

	maybe_hold_for_parent_probe(cfg);

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
	bool parent_setns_child_user = false;
	bool parent_setns_child_pid = false;
	bool parent_setns_child_syslog = false;
	bool parent_pidfd_setns_child = false;
	bool parent_pidfd_setns_child_without_source_cap = false;
	bool retry_after_failed_first_clone = false;
	const char *syslog_name = NULL;
	const char *nested_syslog_name = NULL;
	char *stack;
	int pipefd[2];
	int start_pipe[2] = { -1, -1 };
	int ready_pipe[2] = { -1, -1 };
	int release_pipe[2] = { -1, -1 };
	struct child_cfg cfg;
	pid_t pid;
	int status;
	char buf[4096];
	ssize_t nr;
	int i;
	int err;
	bool need_parent_probe;

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
		} else if (!strcmp(argv[i], "--parent-setns-child-user")) {
			parent_setns_child_user = true;
		} else if (!strcmp(argv[i], "--parent-setns-child-pid")) {
			parent_setns_child_pid = true;
		} else if (!strcmp(argv[i], "--parent-setns-child-syslog")) {
			parent_setns_child_syslog = true;
		} else if (!strcmp(argv[i], "--parent-pidfd-setns-child")) {
			parent_pidfd_setns_child = true;
		} else if (!strcmp(argv[i], "--parent-pidfd-setns-child-without-source-cap")) {
			parent_pidfd_setns_child_without_source_cap = true;
		} else if (!strcmp(argv[i], "--retry-after-failed-first-clone")) {
			retry_after_failed_first_clone = true;
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

	if (retry_after_failed_first_clone) {
		stack = malloc(STACK_SIZE);
		if (!stack) {
			perror("malloc");
			return 1;
		}

		pid = clone(noop_child_main, stack + STACK_SIZE,
			    SIGCHLD | CLONE_NEWUSER, NULL);
		if (pid < 0) {
			dprintf(STDOUT_FILENO, "first_clone_errno=%d\n", errno);
		} else {
			dprintf(STDOUT_FILENO, "first_clone_errno=0\n");
			if (waitpid(pid, &status, 0) < 0) {
				perror("waitpid");
				free(stack);
				return 1;
			}
		}
		free(stack);
	}

	need_parent_probe = parent_setns_child_user || parent_setns_child_pid ||
		parent_setns_child_syslog || parent_pidfd_setns_child ||
		parent_pidfd_setns_child_without_source_cap;

	if (pipe(pipefd) < 0) {
		perror("pipe");
		return 1;
	}
	if (pipe(start_pipe) < 0) {
		perror("pipe");
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	if (need_parent_probe) {
		if (pipe(ready_pipe) < 0 || pipe(release_pipe) < 0) {
			perror("pipe");
			close(start_pipe[0]);
			close(start_pipe[1]);
			return 1;
		}
	}

	stack = malloc(STACK_SIZE);
	if (!stack) {
		perror("malloc");
		if (need_parent_probe) {
			close(ready_pipe[0]);
			close(ready_pipe[1]);
			close(release_pipe[0]);
			close(release_pipe[1]);
		}
		return 1;
	}

	cfg.pipefd = pipefd[1];
	cfg.startfd = start_pipe[0];
	cfg.readyfd = need_parent_probe ?
		ready_pipe[1] : -1;
	cfg.releasefd = need_parent_probe ?
		release_pipe[0] : -1;
	cfg.parent_pid = getpid();
	cfg.nested_attempt = nested_attempt;
	cfg.setns_parent_tracing = setns_parent_tracing;
	cfg.nested_syslog_name = nested_syslog_name;

	pid = clone(child_main, stack + STACK_SIZE,
		    SIGCHLD | CLONE_NEWUSER | CLONE_NEWPID, &cfg);
	if (pid < 0) {
		dprintf(STDOUT_FILENO, "clone_errno=%d\n", errno);
		close(pipefd[0]);
		close(pipefd[1]);
		close(start_pipe[0]);
		close(start_pipe[1]);
		if (need_parent_probe) {
			close(ready_pipe[0]);
			close(ready_pipe[1]);
			close(release_pipe[0]);
			close(release_pipe[1]);
		}
		free(stack);
		return 0;
	}

	close(start_pipe[0]);
	err = setup_child_idmaps(pid);
	if (err)
		dprintf(STDOUT_FILENO, "setup_child_idmap_errno=%d\n", err);
	if (write(start_pipe[1], "S", 1) < 0)
		perror("write");
	close(start_pipe[1]);

	close(pipefd[1]);
	if (need_parent_probe) {
		char ready;

		close(ready_pipe[1]);
		close(release_pipe[0]);
		if (read(ready_pipe[0], &ready, 1) != 1) {
			perror("read");
			close(ready_pipe[0]);
			close(release_pipe[1]);
			free(stack);
			return 1;
		}
		close(ready_pipe[0]);

		if (parent_setns_child_user)
			dprintf(STDOUT_FILENO, "parent_setns_child_user_errno=%d\n",
				probe_userns_setns_errno(pid));
		if (parent_setns_child_pid)
			dprintf(STDOUT_FILENO, "parent_setns_child_pid_errno=%d\n",
				probe_pidns_setns_errno(pid));
		if (parent_setns_child_syslog)
			dprintf(STDOUT_FILENO, "parent_setns_child_syslog_errno=%d\n",
				probe_syslogns_setns_errno(pid));
		if (parent_pidfd_setns_child)
			dprintf(STDOUT_FILENO, "parent_pidfd_setns_child_errno=%d\n",
				probe_pidfd_setns_errno(pid));
		if (parent_pidfd_setns_child_without_source_cap)
			dprintf(STDOUT_FILENO,
				"parent_pidfd_setns_child_without_source_cap_errno=%d\n",
				probe_pidfd_setns_without_source_cap_errno(pid));

		if (write(release_pipe[1], "R", 1) < 0)
			perror("write");
		close(release_pipe[1]);
	}

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
