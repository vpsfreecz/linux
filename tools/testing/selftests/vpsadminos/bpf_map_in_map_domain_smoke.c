// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

enum child_mode {
	CHILD_PRODUCER,
	CHILD_CONSUMER,
};

struct child_cfg {
	enum child_mode mode;
	int startfd;
	int outfd;
	int sockfd;
	int tokenless_fd;
};

struct domain_child {
	pid_t pid;
	char *stack;
	int startfd;
	int outfd;
	int sockfd;
};

static int do_syslog_action(int type, const char *buf, int len)
{
	return syscall(SYS_syslog, type, buf, len);
}

static int bpf_syscall(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(SYS_bpf, cmd, attr, sizeof(*attr));
}

static int create_array_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = 1;

	return bpf_syscall(BPF_MAP_CREATE, &attr);
}

static int create_hash_of_maps(int inner_fd)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH_OF_MAPS;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = 1;
	attr.inner_map_fd = inner_fd;

	return bpf_syscall(BPF_MAP_CREATE, &attr);
}

static int update_outer_map(int outer_fd, int inner_fd)
{
	union bpf_attr attr;
	uint32_t key = 0;
	uint32_t value = inner_fd;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = outer_fd;
	attr.key = (uintptr_t)&key;
	attr.value = (uintptr_t)&value;
	attr.flags = BPF_ANY;

	ret = bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr);
	return ret < 0 ? errno : 0;
}

static int send_fd(int sockfd, int fd)
{
	char control[CMSG_SPACE(sizeof(fd))];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char byte = 'F';

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	return sendmsg(sockfd, &msg, 0) == 1 ? 0 : errno ? errno : EIO;
}

static int recv_fd(int sockfd, int *fd)
{
	char control[CMSG_SPACE(sizeof(*fd))];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char byte;
	ssize_t ret;

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(sockfd, &msg, 0);
	if (ret != 1)
		return ret < 0 ? errno : EIO;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(*fd))) {
		ret = EIO;
		return ret;
	}

	memcpy(fd, CMSG_DATA(cmsg), sizeof(*fd));
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
	char path[128];
	char buf[64];

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
	snprintf(buf, sizeof(buf), "0 %u 1\n", id);
	return write_file(path, buf);
}

static int setup_child_idmaps(pid_t pid)
{
	char path[128];
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

static int wait_for_start(int fd)
{
	char byte;
	ssize_t ret;

	do {
		ret = read(fd, &byte, 1);
	} while (ret < 0 && errno == EINTR);

	if (ret != 1) {
		ret = ret < 0 ? errno : EIO;
		close(fd);
		return ret;
	}

	close(fd);
	return 0;
}

static int report_start_error(struct child_cfg *cfg, int err)
{
	if (!err)
		return 0;

	dprintf(cfg->outfd, "start_errno=%d\n", err);
	close(cfg->outfd);
	close(cfg->sockfd);
	return 1;
}

static int producer_main(struct child_cfg *cfg)
{
	int inner_fd;
	int err = wait_for_start(cfg->startfd);

	if (report_start_error(cfg, err))
		return 1;

	inner_fd = create_array_map();
	if (inner_fd < 0) {
		err = errno;
		dprintf(cfg->outfd, "producer_inner_create_errno=%d\n", err);
		close(cfg->outfd);
		return 1;
	}

	err = send_fd(cfg->sockfd, inner_fd);
	if (err)
		dprintf(cfg->outfd, "producer_send_fd_errno=%d\n", err);

	close(inner_fd);
	close(cfg->sockfd);
	close(cfg->outfd);
	return err ? 1 : 0;
}

static int consumer_main(struct child_cfg *cfg)
{
	int inner_fd, outer_fd, cross_fd = -1;
	int err = wait_for_start(cfg->startfd);
	int recv_errno;

	if (report_start_error(cfg, err))
		return 1;

	inner_fd = create_array_map();
	if (inner_fd < 0) {
		dprintf(cfg->outfd, "consumer_inner_create_errno=%d\n", errno);
		close(cfg->outfd);
		return 1;
	}

	outer_fd = create_hash_of_maps(inner_fd);
	if (outer_fd < 0) {
		dprintf(cfg->outfd, "consumer_outer_create_errno=%d\n", errno);
		close(inner_fd);
		close(cfg->outfd);
		return 1;
	}

	err = update_outer_map(outer_fd, inner_fd);
	dprintf(cfg->outfd, "same_domain_errno=%d\n", err);

	err = update_outer_map(outer_fd, cfg->tokenless_fd);
	dprintf(cfg->outfd, "tokenless_inner_errno=%d\n", err);

	recv_errno = recv_fd(cfg->sockfd, &cross_fd);
	dprintf(cfg->outfd, "cross_domain_recv_errno=%d\n", recv_errno);
	if (!recv_errno) {
		err = update_outer_map(outer_fd, cross_fd);
		dprintf(cfg->outfd, "cross_domain_errno=%d\n", err);
		close(cross_fd);
	}

	close(outer_fd);
	close(inner_fd);
	close(cfg->sockfd);
	close(cfg->outfd);
	return 0;
}

static int child_main(void *arg)
{
	struct child_cfg *cfg = arg;

	if (cfg->mode == CHILD_PRODUCER)
		return producer_main(cfg);

	return consumer_main(cfg);
}

static int cleanup_failed_spawn(struct domain_child *child, int err)
{
	if (child->startfd >= 0)
		close(child->startfd);
	if (child->outfd >= 0)
		close(child->outfd);
	if (child->sockfd >= 0)
		close(child->sockfd);
	if (child->pid > 0)
		waitpid(child->pid, NULL, 0);
	free(child->stack);
	return err;
}

static int spawn_domain_child(enum child_mode mode, const char *name,
			      int tokenless_fd, struct domain_child *child)
{
	int start_pipe[2], out_pipe[2], sock_pair[2];
	struct child_cfg *cfg;
	int err;

	memset(child, 0, sizeof(*child));
	child->startfd = -1;
	child->outfd = -1;
	child->sockfd = -1;

	if (do_syslog_action(SYSLOG_ACTION_NEW_NS, name, strlen(name)) < 0)
		return errno;
	if (do_syslog_action(SYSLOG_ACTION_NEW_TRACING_NS, NULL, 0) < 0)
		return errno;

	if (pipe(start_pipe) < 0)
		return errno;
	if (pipe(out_pipe) < 0) {
		err = errno;
		close(start_pipe[0]);
		close(start_pipe[1]);
		return err;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_pair) < 0) {
		err = errno;
		close(start_pipe[0]);
		close(start_pipe[1]);
		close(out_pipe[0]);
		close(out_pipe[1]);
		return err;
	}

	child->stack = malloc(STACK_SIZE);
	cfg = calloc(1, sizeof(*cfg));
	if (!child->stack || !cfg) {
		err = errno ? errno : ENOMEM;
		free(child->stack);
		free(cfg);
		close(start_pipe[0]);
		close(start_pipe[1]);
		close(out_pipe[0]);
		close(out_pipe[1]);
		close(sock_pair[0]);
		close(sock_pair[1]);
		return err;
	}

	cfg->mode = mode;
	cfg->startfd = start_pipe[0];
	cfg->outfd = out_pipe[1];
	cfg->sockfd = sock_pair[1];
	cfg->tokenless_fd = tokenless_fd;

	child->pid = clone(child_main, child->stack + STACK_SIZE,
			   SIGCHLD | CLONE_NEWUSER | CLONE_NEWPID, cfg);
	if (child->pid < 0) {
		err = errno;
		free(child->stack);
		free(cfg);
		close(start_pipe[0]);
		close(start_pipe[1]);
		close(out_pipe[0]);
		close(out_pipe[1]);
		close(sock_pair[0]);
		close(sock_pair[1]);
		return err;
	}
	free(cfg);

	close(start_pipe[0]);
	close(out_pipe[1]);
	close(sock_pair[1]);
	child->startfd = start_pipe[1];
	child->outfd = out_pipe[0];
	child->sockfd = sock_pair[0];

	err = setup_child_idmaps(child->pid);
	if (err)
		return cleanup_failed_spawn(child, err);

	if (write(child->startfd, "S", 1) != 1)
		return cleanup_failed_spawn(child, errno ? errno : EIO);
	close(child->startfd);
	child->startfd = -1;

	return 0;
}

static int wait_domain_child(struct domain_child *child)
{
	int status;

	if (waitpid(child->pid, &status, 0) < 0)
		return errno;

	free(child->stack);
	child->stack = NULL;

	if (!WIFEXITED(status)) {
		status = ECHILD;
		return status;
	}

	return WEXITSTATUS(status);
}

static int forward_child_output(int outfd)
{
	char buf[4096];
	ssize_t nr;

	while ((nr = read(outfd, buf, sizeof(buf))) > 0) {
		if (write(STDOUT_FILENO, buf, nr) != nr)
			return errno ? errno : EIO;
	}

	return nr < 0 ? errno : 0;
}

int main(void)
{
	struct domain_child producer, consumer;
	char name_a[32], name_b[32];
	int tokenless_fd, cross_fd = -1;
	int err, child_rc;

	tokenless_fd = create_array_map();
	if (tokenless_fd < 0) {
		dprintf(STDOUT_FILENO, "parent_tokenless_create_errno=%d\n", errno);
		return 1;
	}

	snprintf(name_b, sizeof(name_b), "bpfB%ld", (long)getpid());
	err = spawn_domain_child(CHILD_PRODUCER, name_b, -1, &producer);
	if (err) {
		dprintf(STDOUT_FILENO, "producer_spawn_errno=%d\n", err);
		close(tokenless_fd);
		return 1;
	}

	err = recv_fd(producer.sockfd, &cross_fd);
	dprintf(STDOUT_FILENO, "producer_recv_fd_errno=%d\n", err);
	close(producer.sockfd);
	close(producer.outfd);
	child_rc = wait_domain_child(&producer);
	if (err || child_rc) {
		close(tokenless_fd);
		if (cross_fd >= 0)
			close(cross_fd);
		return 1;
	}

	snprintf(name_a, sizeof(name_a), "bpfA%ld", (long)getpid());
	err = spawn_domain_child(CHILD_CONSUMER, name_a, tokenless_fd, &consumer);
	if (err) {
		dprintf(STDOUT_FILENO, "consumer_spawn_errno=%d\n", err);
		close(tokenless_fd);
		close(cross_fd);
		return 1;
	}

	err = send_fd(consumer.sockfd, cross_fd);
	dprintf(STDOUT_FILENO, "consumer_send_fd_errno=%d\n", err);
	close(cross_fd);
	close(consumer.sockfd);

	if (!err)
		err = forward_child_output(consumer.outfd);
	close(consumer.outfd);
	child_rc = wait_domain_child(&consumer);

	close(tokenless_fd);
	return err || child_rc ? 1 : 0;
}
