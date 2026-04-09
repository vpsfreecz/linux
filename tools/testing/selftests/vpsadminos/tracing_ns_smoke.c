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

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

struct child_cfg {
	int pipefd;
	int pipe_readfd;
	int startfd;
	int start_writefd;
	int readyfd;
	int ready_readfd;
	int releasefd;
	int release_writefd;
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
	static const char * const names[] = {
		"user", "pid", "syslog", "tracing"
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
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

static int noop_child_main(void *arg)
{
	(void)arg;
	return 0;
}

static int read_byte(int fd)
{
	char byte;
	ssize_t ret;

	do {
		ret = read(fd, &byte, 1);
	} while (ret < 0 && errno == EINTR);

	return ret == 1 ? 0 : ret < 0 ? errno : EIO;
}

static int write_byte(int fd, char byte)
{
	ssize_t ret;

	do {
		ret = write(fd, &byte, 1);
	} while (ret < 0 && errno == EINTR);

	return ret == 1 ? 0 : ret < 0 ? errno : EIO;
}

static int maybe_hold_for_parent_probe(struct child_cfg *cfg)
{
	int err;

	if (cfg->readyfd < 0 || cfg->releasefd < 0)
		return 0;

	err = write_byte(cfg->readyfd, 'R');
	close(cfg->readyfd);
	if (err) {
		close(cfg->releasefd);
		return err;
	}

	err = read_byte(cfg->releasefd);
	close(cfg->releasefd);
	return err;
}

static int terminate_and_reap_child(pid_t pid)
{
	int status;
	int err = 0;
	pid_t ret;

	if (kill(pid, SIGKILL) < 0 && errno != ESRCH)
		err = errno;

	do {
		ret = waitpid(pid, &status, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0 && errno != ECHILD && !err)
		err = errno;

	return err;
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
		int write_errno;

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
		write_errno =
			write(pipefd[1], &setns_errno, sizeof(setns_errno)) !=
			sizeof(setns_errno);
		close(pipefd[1]);
		_exit(write_errno);
	}

	close(pipefd[1]);
	if (read(pipefd[0], &err, sizeof(err)) != sizeof(err))
		err = EIO;
	close(pipefd[0]);

	if (waitpid(probe, &status, 0) < 0)
		return errno;

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
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

	close(cfg->pipe_readfd);
	close(cfg->start_writefd);
	if (cfg->ready_readfd >= 0)
		close(cfg->ready_readfd);
	if (cfg->release_writefd >= 0)
		close(cfg->release_writefd);

	err = read_byte(cfg->startfd);
	close(cfg->startfd);
	if (err) {
		dprintf(cfg->pipefd, "child_start_errno=%d\n", err);
		close(cfg->pipefd);
		return 1;
	}

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

	err = maybe_hold_for_parent_probe(cfg);
	if (err) {
		dprintf(cfg->pipefd, "child_parent_probe_sync_errno=%d\n",
			err);
		close(cfg->pipefd);
		return 1;
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
	bool retry_after_failed_first_clone = false;
	bool parent_setns_child_user = false;
	bool parent_setns_child_pid = false;
	bool parent_setns_child_syslog = false;
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
	int err = 0;
	bool need_parent_probe;

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		perror("signal");
		return 1;
	}

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
		} else if (!strcmp(argv[i], "--retry-after-failed-first-clone")) {
			retry_after_failed_first_clone = true;
		} else if (!strcmp(argv[i], "--parent-setns-child-user")) {
			parent_setns_child_user = true;
		} else if (!strcmp(argv[i], "--parent-setns-child-pid")) {
			parent_setns_child_pid = true;
		} else if (!strcmp(argv[i], "--parent-setns-child-syslog")) {
			parent_setns_child_syslog = true;
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
		parent_setns_child_syslog;

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
		if (pipe(ready_pipe) < 0) {
			perror("pipe");
			close(pipefd[0]);
			close(pipefd[1]);
			close(start_pipe[0]);
			close(start_pipe[1]);
			return 1;
		}
		if (pipe(release_pipe) < 0) {
			perror("pipe");
			close(pipefd[0]);
			close(pipefd[1]);
			close(start_pipe[0]);
			close(start_pipe[1]);
			close(ready_pipe[0]);
			close(ready_pipe[1]);
			return 1;
		}
	}

	stack = malloc(STACK_SIZE);
	if (!stack) {
		perror("malloc");
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
		return 1;
	}

	cfg.pipefd = pipefd[1];
	cfg.pipe_readfd = pipefd[0];
	cfg.startfd = start_pipe[0];
	cfg.start_writefd = start_pipe[1];
	cfg.parent_pid = getpid();
	cfg.readyfd = need_parent_probe ?
		ready_pipe[1] : -1;
	cfg.ready_readfd = need_parent_probe ?
		ready_pipe[0] : -1;
	cfg.releasefd = need_parent_probe ?
		release_pipe[0] : -1;
	cfg.release_writefd = need_parent_probe ?
		release_pipe[1] : -1;
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
	i = write_byte(start_pipe[1], 'S');
	if (i) {
		fprintf(stderr, "write start byte: %s\n", strerror(i));
		if (!err)
			err = i;
	}
	close(start_pipe[1]);

	close(pipefd[1]);
	if (need_parent_probe) {
		int sync_err;

		close(ready_pipe[1]);
		close(release_pipe[0]);
		sync_err = read_byte(ready_pipe[0]);
		if (sync_err) {
			fprintf(stderr, "read ready byte: %s\n",
				strerror(sync_err));
			close(ready_pipe[0]);
			close(release_pipe[1]);
			close(pipefd[0]);
			terminate_and_reap_child(pid);
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

		sync_err = write_byte(release_pipe[1], 'R');
		if (sync_err) {
			fprintf(stderr, "write release byte: %s\n",
				strerror(sync_err));
			if (!err)
				err = sync_err;
		}
		close(release_pipe[1]);
	}

	while ((nr = read(pipefd[0], buf, sizeof(buf))) > 0) {
		if (write(STDOUT_FILENO, buf, nr) != nr) {
			perror("write");
			close(pipefd[0]);
			terminate_and_reap_child(pid);
			free(stack);
			return 1;
		}
	}
	if (nr < 0 && !err)
		err = errno;
	close(pipefd[0]);

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		free(stack);
		return 1;
	}

	free(stack);
	if (err)
		return 1;
	if (!WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}
