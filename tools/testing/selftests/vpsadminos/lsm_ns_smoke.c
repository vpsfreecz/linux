// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_lsm_set_self_attr
#ifdef __alpha__
#define __NR_lsm_set_self_attr 570
#else
#define __NR_lsm_set_self_attr 460
#endif
#endif

#ifndef __NR_pidfd_open
#ifdef __alpha__
#define __NR_pidfd_open 544
#else
#define __NR_pidfd_open 434
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
	int selinuxfs_err;
	char user_ns[NS_LINK_SIZE];
	char lsm_ns[NS_LINK_SIZE];
};

struct child_cfg {
	int pipefd;
	int waitfd;
	int mount_selinuxfs;
};

enum setns_probe_stage {
	SETNS_PROBE_NONE,
	SETNS_PROBE_PIDFD_OPEN,
	SETNS_PROBE_SETNS,
	SETNS_PROBE_MKDTEMP,
	SETNS_PROBE_MOUNT_SELINUXFS,
	SETNS_PROBE_OPEN_ENFORCE,
	SETNS_PROBE_READ_ENFORCE,
	SETNS_PROBE_WRITE_ENFORCE,
	SETNS_PROBE_OPEN_LOAD,
	SETNS_PROBE_WRITE_LOAD,
	SETNS_PROBE_UMOUNT_SELINUXFS,
	SETNS_PROBE_READ_RESULT,
};

struct setns_probe_result {
	enum setns_probe_stage stage;
	int err;
};

static const char *setns_probe_stage_name(enum setns_probe_stage stage)
{
	switch (stage) {
	case SETNS_PROBE_PIDFD_OPEN:
		return "pidfd_open";
	case SETNS_PROBE_SETNS:
		return "setns";
	case SETNS_PROBE_MKDTEMP:
		return "mkdtemp";
	case SETNS_PROBE_MOUNT_SELINUXFS:
		return "mount_selinuxfs";
	case SETNS_PROBE_OPEN_ENFORCE:
		return "open_enforce";
	case SETNS_PROBE_READ_ENFORCE:
		return "read_enforce";
	case SETNS_PROBE_WRITE_ENFORCE:
		return "write_enforce";
	case SETNS_PROBE_OPEN_LOAD:
		return "open_load";
	case SETNS_PROBE_WRITE_LOAD:
		return "write_load";
	case SETNS_PROBE_UMOUNT_SELINUXFS:
		return "umount_selinuxfs";
	case SETNS_PROBE_READ_RESULT:
		return "read_result";
	case SETNS_PROBE_NONE:
	default:
		return "unknown";
	}
}

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

static int write_text_file(const char *path, const char *text)
{
	int fd;
	int saved_errno;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (write_full(fd, text, strlen(text))) {
		saved_errno = errno ? errno : EIO;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	return close(fd);
}

static int write_child_proc_file(pid_t pid, const char *name, const char *text)
{
	char path[PATH_MAX];
	int ret;

	ret = snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	return write_text_file(path, text);
}

static int map_child_root(pid_t pid)
{
	char map[64];
	int ret;

	if (write_child_proc_file(pid, "setgroups", "deny\n") && errno != ENOENT)
		return -1;

	ret = snprintf(map, sizeof(map), "0 %lu 1\n", (unsigned long)getuid());
	if (ret < 0 || (size_t)ret >= sizeof(map)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (write_child_proc_file(pid, "uid_map", map))
		return -1;

	ret = snprintf(map, sizeof(map), "0 %lu 1\n", (unsigned long)getgid());
	if (ret < 0 || (size_t)ret >= sizeof(map)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return write_child_proc_file(pid, "gid_map", map);
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

static int try_mount_selinuxfs(void)
{
	char path[] = "/tmp/vpsadminos-selinuxfs-XXXXXX";
	int saved_errno;

	if (!mkdtemp(path))
		return -1;

	if (mount("selinuxfs", path, "selinuxfs", 0, NULL)) {
		saved_errno = errno;
		rmdir(path);
		errno = saved_errno;
		return -1;
	}

	if (umount2(path, MNT_DETACH)) {
		saved_errno = errno;
		rmdir(path);
		errno = saved_errno;
		return -1;
	}

	return rmdir(path);
}

static int try_invalid_policy_load(enum setns_probe_stage *stage)
{
	char path[] = "/tmp/vpsadminos-selinuxfs-load-XXXXXX";
	char enforce_path[PATH_MAX];
	char load_path[PATH_MAX];
	char enforce_buf[16];
	char new_enforce;
	int fd = -1;
	int ret = -1;
	int saved_errno;
	ssize_t nread;

	if (!mkdtemp(path)) {
		*stage = SETNS_PROBE_MKDTEMP;
		return -1;
	}

	if (mount("selinuxfs", path, "selinuxfs", 0, NULL)) {
		saved_errno = errno;
		*stage = SETNS_PROBE_MOUNT_SELINUXFS;
		goto out_rmdir;
	}

	snprintf(enforce_path, sizeof(enforce_path), "%s/enforce", path);
	fd = open(enforce_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		saved_errno = errno;
		*stage = SETNS_PROBE_OPEN_ENFORCE;
		goto out_umount;
	}

	nread = read(fd, enforce_buf, sizeof(enforce_buf) - 1);
	if (nread < 0) {
		saved_errno = errno;
		*stage = SETNS_PROBE_READ_ENFORCE;
		goto out_close_enforce;
	}
	enforce_buf[nread] = '\0';
	new_enforce = enforce_buf[0] == '0' ? '1' : '0';
	if (lseek(fd, 0, SEEK_SET) < 0) {
		saved_errno = errno;
		*stage = SETNS_PROBE_WRITE_ENFORCE;
		goto out_close_enforce;
	}
	if (write(fd, &new_enforce, 1) != 1) {
		saved_errno = errno;
		*stage = SETNS_PROBE_WRITE_ENFORCE;
		goto out_close_enforce;
	}
	close(fd);
	fd = -1;

	snprintf(load_path, sizeof(load_path), "%s/load", path);
	fd = open(load_path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		saved_errno = errno;
		*stage = SETNS_PROBE_OPEN_LOAD;
		goto out_umount;
	}

	if (write(fd, "x", 1) < 0) {
		saved_errno = errno;
		ret = saved_errno == EINVAL ? 0 : -1;
		if (ret)
			*stage = SETNS_PROBE_WRITE_LOAD;
	} else {
		saved_errno = EIO;
		*stage = SETNS_PROBE_WRITE_LOAD;
	}

	close(fd);
	fd = -1;
out_close_enforce:
	if (fd >= 0)
		close(fd);
out_umount:
	if (umount2(path, MNT_DETACH) && ret == 0) {
		saved_errno = errno;
		*stage = SETNS_PROBE_UMOUNT_SELINUXFS;
		ret = -1;
	}
out_rmdir:
	rmdir(path);
	errno = saved_errno;
	return ret;
}

static int host_selinux_active(void)
{
	return access("/sys/fs/selinux/enforce", F_OK) == 0;
}

static int child_main(void *arg)
{
	struct child_cfg *cfg = arg;
	struct child_result result = { .err = 0 };
	char release;

	if (read_ns_link("user", result.user_ns, sizeof(result.user_ns)) ||
	    read_ns_link("lsm", result.lsm_ns, sizeof(result.lsm_ns)))
		result.err = errno ? errno : EIO;

	if (!result.err && cfg->mount_selinuxfs && try_mount_selinuxfs()) {
		result.selinuxfs_err = errno ? errno : EIO;
		result.err = result.selinuxfs_err;
	}

	if (write_full(cfg->pipefd, &result, sizeof(result)) && !result.err)
		result.err = errno ? errno : EIO;
	close(cfg->pipefd);

	if (cfg->waitfd >= 0) {
		while (read(cfg->waitfd, &release, 1) < 0 && errno == EINTR)
			;
		close(cfg->waitfd);
	}

	return result.err ? 1 : 0;
}

static pid_t clone_child_wait(struct child_result *result, int mount_selinuxfs,
			      int *release_fd)
{
	struct child_cfg cfg;
	char *stack;
	char *stack_top;
	int pipefd[2];
	int waitfd[2] = { -1, -1 };
	pid_t pid;
	int saved_errno;
	int clone_flags = CLONE_NEWUSER | SIGCHLD;

	if (pipe(pipefd) < 0)
		return -1;

	if (release_fd && pipe(waitfd) < 0) {
		saved_errno = errno;
		close(pipefd[0]);
		close(pipefd[1]);
		errno = saved_errno;
		return -1;
	}

	stack = malloc(STACK_SIZE);
	if (!stack) {
		saved_errno = ENOMEM;
		close(pipefd[0]);
		close(pipefd[1]);
		if (release_fd) {
			close(waitfd[0]);
			close(waitfd[1]);
		}
		errno = saved_errno;
		return -1;
	}

	cfg.pipefd = pipefd[1];
	cfg.waitfd = release_fd ? waitfd[0] : -1;
	cfg.mount_selinuxfs = mount_selinuxfs;
	stack_top = stack + STACK_SIZE;
	if (mount_selinuxfs)
		clone_flags |= CLONE_NEWNS;

	pid = clone(child_main, stack_top, clone_flags, &cfg);
	saved_errno = errno;
	close(pipefd[1]);
	if (release_fd)
		close(waitfd[0]);

	if (pid < 0) {
		close(pipefd[0]);
		if (release_fd)
			close(waitfd[1]);
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
	free(stack);

	if (result->err) {
		saved_errno = result->err;
		if (release_fd) {
			if (write_full(waitfd[1], "x", 1) && !saved_errno)
				saved_errno = errno ? errno : EIO;
			close(waitfd[1]);
		}
		waitpid(pid, NULL, 0);
		errno = saved_errno;
		return -1;
	}

	if (release_fd) {
		*release_fd = waitfd[1];
		return pid;
	}

	return pid;
}

static int release_child(pid_t pid, int release_fd)
{
	int status;
	int saved_errno = 0;

	if (release_fd >= 0) {
		if (write_full(release_fd, "x", 1))
			saved_errno = errno ? errno : EIO;
		close(release_fd);
	}
	if (waitpid(pid, &status, 0) < 0) {
		return -1;
	}
	if (saved_errno) {
		errno = saved_errno;
		return -1;
	}

	if (!WIFEXITED(status)) {
		errno = ECHILD;
		return -1;
	}
	if (WEXITSTATUS(status)) {
		errno = ECHILD;
		return -1;
	}

	return 0;
}

static int clone_child(struct child_result *result, int mount_selinuxfs)
{
	pid_t pid = clone_child_wait(result, mount_selinuxfs, NULL);

	if (pid < 0)
		return -1;

	return release_child(pid, -1);
}

static int pidfd_setns_invalid_load(pid_t target, enum setns_probe_stage *stage)
{
	struct setns_probe_result result = { 0 };
	int pipefd[2];
	pid_t pid;
	int err;
	int status;

	*stage = SETNS_PROBE_NONE;
	if (pipe(pipefd) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		err = errno;
		close(pipefd[0]);
		close(pipefd[1]);
		errno = err;
		return -1;
	}

	if (pid == 0) {
		int pidfd;
		struct setns_probe_result child_result = { 0 };

		close(pipefd[0]);
		pidfd = syscall(__NR_pidfd_open, target, 0);
		if (pidfd < 0) {
			child_result.stage = SETNS_PROBE_PIDFD_OPEN;
			child_result.err = errno;
			write_full(pipefd[1], &child_result, sizeof(child_result));
			_exit(1);
		}

		if (setns(pidfd, CLONE_NEWUSER | CLONE_NEWNS)) {
			child_result.stage = SETNS_PROBE_SETNS;
			child_result.err = errno;
			close(pidfd);
			write_full(pipefd[1], &child_result, sizeof(child_result));
			_exit(1);
		}
		close(pidfd);

		if (try_invalid_policy_load(&child_result.stage)) {
			child_result.err = errno;
			write_full(pipefd[1], &child_result, sizeof(child_result));
			_exit(1);
		}

		write_full(pipefd[1], &child_result, sizeof(child_result));
		_exit(0);
	}

	close(pipefd[1]);
	if (read_full(pipefd[0], &result, sizeof(result))) {
		result.err = errno ? errno : EIO;
		result.stage = SETNS_PROBE_READ_RESULT;
	}
	close(pipefd[0]);

	if (waitpid(pid, &status, 0) < 0)
		return -1;

	if (result.err) {
		*stage = result.stage;
		errno = result.err;
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		errno = ECHILD;
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
			   const char *parent_lsm_ns, int mount_selinuxfs)
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

	if (clone_child(&child, mount_selinuxfs)) {
		if (child.selinuxfs_err) {
			printf("not ok %d failed to mount selinuxfs in child "
			       "SELinux LSM namespace\n", nr);
			errno = child.selinuxfs_err;
			perror("mount(selinuxfs)");
			return 1;
		}

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

	printf("ok %d child user namespace consumed %s LSM namespace request%s\n",
	       nr, label,
	       mount_selinuxfs ? " and mounted selinuxfs" : "");
	return 0;
}

static int run_selinux_pidfd_setns_test(int nr, const char *parent_user_ns,
					const char *parent_lsm_ns)
{
	struct child_result child = { 0 };
	enum setns_probe_stage stage;
	int release_fd = -1;
	pid_t pid;

	if (request_lsm_ns(LSM_ID_SELINUX, NULL)) {
		if (skip_errno(errno)) {
			printf("ok %d # SKIP cannot arm SELinux LSM namespace request: %s\n",
			       nr, strerror(errno));
			return KSFT_SKIP;
		}

		printf("not ok %d failed to arm SELinux LSM namespace request\n", nr);
		perror("lsm_set_self_attr(LSM_ATTR_UNSHARE)");
		return 1;
	}

	/*
	 * The pidfd attach probe needs a child-owned mount namespace.  Joining
	 * a child user namespace while keeping the parent-owned mount namespace
	 * correctly leaves the helper without CAP_SYS_ADMIN for new mounts.
	 */
	pid = clone_child_wait(&child, 1, &release_fd);
	if (pid < 0) {
		if (child.selinuxfs_err) {
			printf("not ok %d failed to prepare child SELinux mount namespace\n",
			       nr);
			errno = child.selinuxfs_err;
			perror("mount(selinuxfs)");
			return 1;
		}

		if (skip_errno(errno)) {
			printf("ok %d # SKIP cannot create child SELinux LSM namespace: %s\n",
			       nr, strerror(errno));
			return KSFT_SKIP;
		}

		printf("not ok %d failed to create waiting SELinux LSM namespace child\n",
		       nr);
		perror("clone(CLONE_NEWUSER)");
		return 1;
	}

	if (!strcmp(parent_user_ns, child.user_ns) ||
	    !strcmp(parent_lsm_ns, child.lsm_ns)) {
		printf("not ok %d waiting child did not enter child user/LSM namespace\n",
		       nr);
		release_child(pid, release_fd);
		return 1;
	}

	/*
	 * The helper enters the child's user namespace before mounting
	 * selinuxfs.  Give that namespace the minimal root id mapping a CT-level
	 * attach path has, otherwise DAC rejects opening selinuxfs/load before
	 * the probe reaches SELinux state selection.
	 */
	if (map_child_root(pid)) {
		int err = errno;

		release_child(pid, release_fd);
		if (err == EPERM || err == EACCES) {
			printf("ok %d # SKIP cannot map child user namespace ids: %s\n",
			       nr, strerror(err));
			return KSFT_SKIP;
		}

		printf("not ok %d failed to map child user namespace ids: %s\n",
		       nr, strerror(err));
		return 1;
	}

	if (pidfd_setns_invalid_load(pid, &stage)) {
		int err = errno;

		release_child(pid, release_fd);
		if (err == ENOSYS) {
			printf("ok %d # SKIP pidfd_open unavailable\n", nr);
			return KSFT_SKIP;
		}

		printf("not ok %d pidfd setns SELinux child policy load failed at %s: %s\n",
		       nr, setns_probe_stage_name(stage), strerror(err));
		return 1;
	}

	if (release_child(pid, release_fd)) {
		printf("not ok %d waiting SELinux child did not exit cleanly\n", nr);
		perror("waitpid");
		return 1;
	}

	printf("ok %d pidfd setns uses child SELinux state for selinuxfs policy load\n",
	       nr);
	return 0;
}

static int run_selinux_invalid_outer_context_test(int nr)
{
	struct child_result child = { 0 };
	const char *invalid = "not-a-valid-selinux-context";
	int err;

	if (!host_selinux_active()) {
		printf("ok %d # SKIP host SELinux is not active\n", nr);
		return KSFT_SKIP;
	}

	if (request_lsm_ns(LSM_ID_SELINUX, invalid)) {
		err = errno;
		if (err == EINVAL) {
			printf("ok %d invalid SELinux outer context rejected at arm time\n",
			       nr);
			return 0;
		}
		if (skip_errno(err)) {
			printf("ok %d # SKIP cannot arm SELinux LSM namespace request: %s\n",
			       nr, strerror(err));
			return KSFT_SKIP;
		}

		printf("not ok %d unexpected failure arming invalid SELinux outer context: %s\n",
		       nr, strerror(err));
		return 1;
	}

	if (clone_child(&child, 0)) {
		err = errno;
		if (err == EINVAL) {
			printf("ok %d invalid SELinux outer context rejected at child creation\n",
			       nr);
			return 0;
		}
		if (skip_errno(err)) {
			printf("ok %d # SKIP cannot create child SELinux LSM namespace: %s\n",
			       nr, strerror(err));
			return KSFT_SKIP;
		}

		printf("not ok %d unexpected child creation failure for invalid SELinux outer context: %s\n",
		       nr, strerror(err));
		return 1;
	}

	printf("not ok %d invalid SELinux outer context was accepted\n", nr);
	return 1;
}

int main(void)
{
	char parent_user_ns[NS_LINK_SIZE];
	char parent_lsm_ns[NS_LINK_SIZE];
	int apparmor_ret, selinux_ret, selinux_setns_ret, selinux_outer_ret;

	if (read_ns_link("lsm", parent_lsm_ns, sizeof(parent_lsm_ns))) {
		printf("TAP version 13\n1..0 # SKIP no lsm namespace file\n");
		return KSFT_SKIP;
	}
	if (read_ns_link("user", parent_user_ns, sizeof(parent_user_ns))) {
		perror("read parent user namespace");
		return 1;
	}

	printf("TAP version 13\n");
	printf("1..4\n");

	apparmor_ret = run_lsm_ns_test(1, "AppArmor", LSM_ID_APPARMOR,
				       "selftest-lsmns", parent_user_ns,
				       parent_lsm_ns, 0);
	selinux_ret = run_lsm_ns_test(2, "SELinux", LSM_ID_SELINUX, NULL,
				      parent_user_ns, parent_lsm_ns, 1);
	selinux_setns_ret = run_selinux_pidfd_setns_test(3, parent_user_ns,
							 parent_lsm_ns);
	selinux_outer_ret = run_selinux_invalid_outer_context_test(4);

	if (apparmor_ret == 1 || selinux_ret == 1 || selinux_setns_ret == 1 ||
	    selinux_outer_ret == 1)
		return 1;
	if (apparmor_ret == KSFT_SKIP && selinux_ret == KSFT_SKIP &&
	    selinux_setns_ret == KSFT_SKIP && selinux_outer_ret == KSFT_SKIP)
		return KSFT_SKIP;
	return 0;
}
