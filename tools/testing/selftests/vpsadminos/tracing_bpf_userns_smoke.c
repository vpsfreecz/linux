// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../../include/linux/filter.h"

#ifndef BPF_NOSPEC
#define BPF_NOSPEC 0xc0
#endif

#define RAW_BTF_INFO_ENC(kind, kind_flag, vlen) \
	(((!!(kind_flag)) << 31) | ((kind) << 24) | ((vlen) & 0xffff))
#define RAW_BTF_INT_ENC(encoding, bits_offset, nr_bits) \
	((encoding) << 24 | (bits_offset) << 16 | (nr_bits))

#ifndef SYSLOG_ACTION_NEW_NS
#define SYSLOG_ACTION_NEW_NS 11
#endif
#ifndef SYSLOG_ACTION_NEW_TRACING_NS
#define SYSLOG_ACTION_NEW_TRACING_NS 12
#endif

#ifndef STACK_SIZE
#define STACK_SIZE (1024 * 1024)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#define VERIFIER_LOG_SIZE (64 * 1024)

struct cgroup_fixture {
	char base_path[PATH_MAX];
	char container_path[PATH_MAX];
	char peer_path[PATH_MAX];
	int root_fd;
	int container_fd;
	int peer_fd;
	int host_prog_fd;
	bool base_created;
	bool container_created;
	bool peer_created;
	bool host_prog_attached;
};

struct child_cfg {
	int pipefd;
	int parent_read_fd;
	int syncfd;
	int sync_write_fd;
	int fdpass;
	int parent_fdpass;
	const char *symbol;
	const struct cgroup_fixture *cgroup;
};

enum xlated_fd_kind {
	XLATED_FD_INVALID = 0,
	XLATED_FD_VAR_STACK = 1,
	XLATED_FD_LOOP_CALLBACK,
	XLATED_FD_MAX_STACK,
};

struct xlated_fd_msg {
	uint32_t kind;
};

static char verifier_log[VERIFIER_LOG_SIZE];
static int xlated_fdpass = -1;

static void close_fd(int *fd)
{
	if (*fd < 0)
		return;

	close(*fd);
	*fd = -1;
}

static int send_xlated_fd(int sock, enum xlated_fd_kind kind, int prog_fd)
{
	char control[CMSG_SPACE(sizeof(prog_fd))] = {};
	struct xlated_fd_msg payload = { .kind = kind };
	struct iovec iov = {
		.iov_base = &payload,
		.iov_len = sizeof(payload),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	ssize_t ret;

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(prog_fd));
	memcpy(CMSG_DATA(cmsg), &prog_fd, sizeof(prog_fd));

	do {
		ret = sendmsg(sock, &msg, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -errno;
	if (ret != (ssize_t)sizeof(payload))
		return -EIO;
	return 0;
}

static int recv_xlated_fd(int sock, enum xlated_fd_kind *kind, int *prog_fd)
{
	char control[CMSG_SPACE(sizeof(*prog_fd))] = {};
	struct xlated_fd_msg payload = {};
	struct iovec iov = {
		.iov_base = &payload,
		.iov_len = sizeof(payload),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;
	ssize_t ret;

	do {
		ret = recvmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	if (!ret)
		return 0;
	if (ret < 0)
		return -errno;
	if (ret != (ssize_t)sizeof(payload) ||
	    msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC))
		return -EPROTO;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(*prog_fd)))
		return -EPROTO;

	memcpy(prog_fd, CMSG_DATA(cmsg), sizeof(*prog_fd));
	*kind = payload.kind;
	return 1;
}

static int waitpid_exact(pid_t pid, int *status)
{
	pid_t ret;

	do {
		ret = waitpid(pid, status, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return errno;
	if (ret != pid)
		return ECHILD;
	return 0;
}

static int abort_child(pid_t pid, int *pipe_read_fd, int *sync_write_fd)
{
	int ret;
	int err = 0;
	int status;

	close_fd(pipe_read_fd);
	close_fd(sync_write_fd);

	if (kill(pid, SIGKILL) < 0 && errno != ESRCH)
		err = errno;

	ret = waitpid_exact(pid, &status);
	if (ret && !err)
		err = ret;
	return err;
}

static int drop_and_verify_bpf_admin_caps(void)
{
	static const unsigned int caps[] = { CAP_BPF, CAP_SYS_ADMIN };
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {};
	size_t i;

	if (syscall(SYS_capget, &hdr, data) < 0)
		return errno;

	for (i = 0; i < ARRAY_SIZE(caps); i++) {
		unsigned int index = caps[i] / 32;
		__u32 mask = 1U << (caps[i] % 32);

		data[index].effective &= ~mask;
		data[index].permitted &= ~mask;
		data[index].inheritable &= ~mask;
	}

	if (syscall(SYS_capset, &hdr, data) < 0)
		return errno;

	memset(data, 0, sizeof(data));
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;
	if (syscall(SYS_capget, &hdr, data) < 0)
		return errno;

	for (i = 0; i < ARRAY_SIZE(caps); i++) {
		unsigned int index = caps[i] / 32;
		__u32 mask = 1U << (caps[i] % 32);

		if ((data[index].effective |
		     data[index].permitted |
		     data[index].inheritable) & mask)
			return EPROTO;
	}

	return 0;
}

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
	static const char * const names[] = { "user", "tracing", "cgroup" };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
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

static int load_program_errno(enum bpf_prog_type prog_type,
			      enum bpf_attach_type attach_type,
			      const struct bpf_insn *insns, size_t insn_cnt,
			      int *prog_fd)
{
	static const char license[] = "GPL";
	union bpf_attr attr = {
		.prog_type = prog_type,
		.expected_attach_type = attach_type,
		.insn_cnt = insn_cnt,
		.insns = (uintptr_t)insns,
		.license = (uintptr_t)license,
		.log_buf = (uintptr_t)verifier_log,
		.log_size = sizeof(verifier_log),
		.log_level = 1,
	};
	int fd;

	memset(verifier_log, 0, sizeof(verifier_log));
	fd = do_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0)
		return errno;

	if (prog_fd)
		*prog_fd = fd;
	else
		close(fd);
	return 0;
}

static int load_sysctl_loop_btf(void)
{
	struct raw_btf {
		struct btf_header hdr;
		uint32_t types[25];
		char strs[25];
	} raw = {
		.hdr = {
			.magic = BTF_MAGIC,
			.version = BTF_VERSION,
			.hdr_len = sizeof(struct btf_header),
			.type_len = sizeof(((struct raw_btf *)0)->types),
			.str_off = sizeof(((struct raw_btf *)0)->types),
			.str_len = sizeof(((struct raw_btf *)0)->strs),
		},
		.types = {
			1, RAW_BTF_INFO_ENC(BTF_KIND_INT, 0, 0), 4,
			RAW_BTF_INT_ENC(BTF_INT_SIGNED, 0, 32),
			0, RAW_BTF_INFO_ENC(BTF_KIND_PTR, 0, 0), 0,
			0, RAW_BTF_INFO_ENC(BTF_KIND_FUNC_PROTO, 0, 1), 1,
			7, 2,
			0, RAW_BTF_INFO_ENC(BTF_KIND_FUNC_PROTO, 0, 2), 1,
			5, 1, 7, 2,
			20, RAW_BTF_INFO_ENC(BTF_KIND_FUNC, 0, 0), 3,
			11, RAW_BTF_INFO_ENC(BTF_KIND_FUNC, 0, 0), 4,
		},
		.strs = "\0int\0i\0ctx\0callback\0main",
	};
	union bpf_attr attr = {};
	int fd;

	attr.btf = (uintptr_t)&raw;
	attr.btf_size = offsetof(struct raw_btf, strs) + sizeof(raw.strs);
	fd = do_bpf(BPF_BTF_LOAD, &attr, sizeof(attr));
	if (fd < 0)
		return -errno;
	return fd;
}

static int
load_program_with_func_info_errno(enum bpf_prog_type prog_type,
				  enum bpf_attach_type attach_type,
				  const struct bpf_insn *insns,
				  size_t insn_cnt, uint32_t callback_insn,
				  int *prog_fd)
{
	static const char license[] = "GPL";
	struct bpf_func_info func_info[] = {
		{ .insn_off = 0, .type_id = 5 },
		{ .insn_off = callback_insn, .type_id = 6 },
	};
	union bpf_attr attr = {};
	int saved_errno;
	int btf_fd;
	int fd;

	btf_fd = load_sysctl_loop_btf();
	if (btf_fd < 0)
		return -btf_fd;

	attr.prog_type = prog_type;
	attr.expected_attach_type = attach_type;
	attr.insn_cnt = insn_cnt;
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)license;
	attr.prog_btf_fd = btf_fd;
	attr.func_info_rec_size = sizeof(func_info[0]);
	attr.func_info_cnt = ARRAY_SIZE(func_info);
	attr.func_info = (uintptr_t)func_info;
	attr.log_buf = (uintptr_t)verifier_log;
	attr.log_size = sizeof(verifier_log);
	attr.log_level = 1;

	memset(verifier_log, 0, sizeof(verifier_log));
	fd = do_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	saved_errno = errno;
	close(btf_fd);
	if (fd < 0)
		return saved_errno;

	if (prog_fd)
		*prog_fd = fd;
	else
		close(fd);
	return 0;
}

static int get_program_id(int prog_fd, uint32_t *id)
{
	struct bpf_prog_info info = {};
	union bpf_attr attr = {};

	attr.info.bpf_fd = prog_fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = (uintptr_t)&info;
	if (do_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0)
		return errno;
	if (!info.id)
		return EPROTO;

	*id = info.id;
	return 0;
}

static int load_libbpf_probe_errno(enum bpf_prog_type prog_type,
				   enum bpf_attach_type attach_type,
				   const struct bpf_insn *insns,
				   size_t insn_cnt, const char *name,
				   const char *license, uint32_t kern_version,
				   int *prog_fd)
{
	union bpf_attr attr = {
		.prog_type = prog_type,
		.expected_attach_type = attach_type,
		.insn_cnt = insn_cnt,
		.insns = (uintptr_t)insns,
		.license = (uintptr_t)license,
		.log_buf = (uintptr_t)verifier_log,
		.log_size = sizeof(verifier_log),
		.log_level = 1,
		.kern_version = kern_version,
	};
	int fd;

	if (name)
		snprintf(attr.prog_name, sizeof(attr.prog_name), "%s", name);

	memset(verifier_log, 0, sizeof(verifier_log));
	fd = do_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0)
		return errno;

	if (prog_fd)
		*prog_fd = fd;
	else
		close(fd);
	return 0;
}

static int create_cgroup_link_errno(int prog_fd, int cgroup_fd,
				    enum bpf_attach_type attach_type)
{
	union bpf_attr attr = {
		.link_create.prog_fd = prog_fd,
		.link_create.target_fd = cgroup_fd,
		.link_create.attach_type = attach_type,
	};
	int fd;

	fd = do_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int prog_info_errno(int prog_fd)
{
	struct bpf_prog_info info = {};
	union bpf_attr attr = {};

	attr.info.bpf_fd = prog_fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = (uintptr_t)&info;
	if (do_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0)
		return errno;
	return 0;
}

static int prog_test_run_errno(int prog_fd)
{
	union bpf_attr attr = {
		.test.prog_fd = prog_fd,
	};

	if (do_bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr)) < 0)
		return errno;
	return 0;
}

static int prog_pin_errno(int prog_fd)
{
	static const char path[] =
		"/sys/fs/bpf/vpsadminos-libbpf-probe-must-not-pin";
	union bpf_attr attr = {
		.pathname = (uintptr_t)path,
		.bpf_fd = prog_fd,
	};

	if (do_bpf(BPF_OBJ_PIN, &attr, sizeof(attr)) < 0)
		return errno;
	return 0;
}

static int prog_bind_map_errno(int prog_fd, int map_fd)
{
	union bpf_attr attr = {
		.prog_bind_map.prog_fd = prog_fd,
		.prog_bind_map.map_fd = map_fd,
	};

	if (do_bpf(BPF_PROG_BIND_MAP, &attr, sizeof(attr)) < 0)
		return errno;
	return 0;
}

static int prog_raw_tracepoint_errno(int prog_fd)
{
	static const char name[] = "sched_switch";
	union bpf_attr attr = {
		.raw_tracepoint.prog_fd = prog_fd,
		.raw_tracepoint.name = (uintptr_t)name,
	};
	int fd;

	fd = do_bpf(BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int prog_stream_read_errno(int prog_fd)
{
	char buf[1];
	union bpf_attr attr = {
		.prog_stream_read.prog_fd = prog_fd,
		.prog_stream_read.stream_buf = (uintptr_t)buf,
		.prog_stream_read.stream_buf_len = sizeof(buf),
	};

	if (do_bpf(BPF_PROG_STREAM_READ_BY_FD, &attr, sizeof(attr)) < 0)
		return errno;
	return 0;
}

static int prog_array_update_errno(int map_fd, int prog_fd)
{
	uint32_t key = 0;
	uint32_t value = prog_fd;
	union bpf_attr attr = {
		.map_fd = map_fd,
		.key = (uintptr_t)&key,
		.value = (uintptr_t)&value,
		.flags = BPF_ANY,
	};

	if (do_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0)
		return errno;
	return 0;
}

static int prog_fdinfo_fields(int prog_fd)
{
	static const char * const fields[] = {
		"prog_type:",
		"prog_jited:",
		"prog_tag:",
		"prog_id:",
		"verified_insns:",
	};
	char path[64];
	char line[256];
	FILE *fp;
	size_t i;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", prog_fd);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;

	while (fgets(line, sizeof(line), fp)) {
		for (i = 0; i < ARRAY_SIZE(fields); i++) {
			if (!strncmp(line, fields[i], strlen(fields[i]))) {
				fclose(fp);
				return 1;
			}
		}
	}

	if (ferror(fp)) {
		int err = errno ?: EIO;

		fclose(fp);
		return -err;
	}

	fclose(fp);
	return 0;
}

static int attach_program_errno(int prog_fd, int cgroup_fd,
				enum bpf_attach_type attach_type,
				uint32_t attach_flags)
{
	union bpf_attr attr = {
		.target_fd = cgroup_fd,
		.attach_bpf_fd = prog_fd,
		.attach_type = attach_type,
		.attach_flags = attach_flags,
	};

	if (do_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0)
		return errno;
	return 0;
}

static int detach_program_errno(int prog_fd, int cgroup_fd,
				enum bpf_attach_type attach_type)
{
	union bpf_attr attr = {
		.target_fd = cgroup_fd,
		.attach_bpf_fd = prog_fd,
		.attach_type = attach_type,
	};

	if (do_bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) < 0)
		return errno;
	return 0;
}

static int query_programs_errno(int cgroup_fd,
				enum bpf_attach_type attach_type,
				uint32_t query_flags, uint32_t *prog_ids,
				uint32_t *prog_cnt)
{
	union bpf_attr attr = {
		.query.target_fd = cgroup_fd,
		.query.attach_type = attach_type,
		.query.query_flags = query_flags,
		.query.prog_ids = (uintptr_t)prog_ids,
		.query.prog_cnt = *prog_cnt,
	};
	int err = 0;

	if (do_bpf(BPF_PROG_QUERY, &attr, sizeof(attr)) < 0)
		err = errno;
	*prog_cnt = attr.query.prog_cnt;
	return err;
}

static int get_xlated_program(int prog_fd, struct bpf_insn **insns,
			      size_t *insn_cnt)
{
	struct bpf_prog_info info = {};
	union bpf_attr attr = {};
	struct bpf_insn *buf;
	uint32_t xlated_len;

	attr.info.bpf_fd = prog_fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = (uintptr_t)&info;
	if (do_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0)
		return errno;
	if (!info.xlated_prog_len ||
	    info.xlated_prog_len % sizeof(struct bpf_insn))
		return EPROTO;

	xlated_len = info.xlated_prog_len;
	buf = malloc(xlated_len);
	if (!buf)
		return ENOMEM;

	memset(&info, 0, sizeof(info));
	info.xlated_prog_len = xlated_len;
	info.xlated_prog_insns = (uintptr_t)buf;
	attr.info.info_len = sizeof(info);
	if (do_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0) {
		int err = errno;

		free(buf);
		return err;
	}

	*insns = buf;
	*insn_cnt = info.xlated_prog_len / sizeof(struct bpf_insn);
	return 0;
}

static bool xlated_has_nospec_stack_add(const struct bpf_insn *insns,
					size_t insn_cnt)
{
	size_t i;

	for (i = 0; i + 1 < insn_cnt; i++) {
		if (insns[i].code != (BPF_ST | BPF_NOSPEC))
			continue;
		if (insns[i + 1].code == (BPF_ALU64 | BPF_ADD | BPF_X) &&
		    (insns[i + 1].dst_reg == BPF_REG_2 ||
		     insns[i + 1].src_reg == BPF_REG_2))
			return true;
	}

	return false;
}

static int xlated_stack_zero_count(const struct bpf_insn *insns,
				   size_t insn_cnt)
{
	uint64_t seen = 0;
	size_t i;

	for (i = 0; i < insn_cnt; i++) {
		int slot;

		if (insns[i].code != (BPF_ST | BPF_MEM | BPF_DW) ||
		    insns[i].dst_reg != BPF_REG_FP || insns[i].imm != 0 ||
		    insns[i].off >= 0 || insns[i].off < -MAX_BPF_STACK ||
		    insns[i].off % 8)
			continue;
		slot = (-insns[i].off / 8) - 1;
		seen |= UINT64_C(1) << slot;
	}

	return __builtin_popcountll(seen);
}

static int xlated_program_hidden(int prog_fd)
{
	struct bpf_prog_info info = {};
	union bpf_attr attr = {};

	attr.info.bpf_fd = prog_fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = (uintptr_t)&info;
	if (do_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0)
		return -errno;
	if (info.xlated_prog_len)
		return -EACCES;
	return 0;
}

static int emit_host_xlated_checks(int fdpass)
{
	bool seen_var_stack = false;
	bool seen_loop_callback = false;
	bool seen_max_stack = false;
	int first_err = 0;
	int ret;

	for (;;) {
		enum xlated_fd_kind kind = XLATED_FD_INVALID;
		struct bpf_insn *xlated = NULL;
		size_t xlated_cnt = 0;
		bool has_nospec;
		int prog_fd = -1;
		int zero_count;
		int err;

		ret = recv_xlated_fd(fdpass, &kind, &prog_fd);
		if (ret <= 0)
			break;

		err = get_xlated_program(prog_fd, &xlated, &xlated_cnt);
		switch (kind) {
		case XLATED_FD_VAR_STACK:
			if (seen_var_stack && !first_err)
				first_err = EPROTO;
			seen_var_stack = true;
			printf("container_var_stack_xlated_errno=%d\n", err);
			if (!err) {
				has_nospec = xlated_has_nospec_stack_add(xlated,
									 xlated_cnt);
				zero_count = xlated_stack_zero_count(xlated,
								     xlated_cnt);
				printf("container_var_stack_nospec=%d\n",
				       has_nospec);
				printf("container_var_stack_zero_init_count=%d\n",
				       zero_count);
			}
			break;
		case XLATED_FD_LOOP_CALLBACK:
			if (seen_loop_callback && !first_err)
				first_err = EPROTO;
			seen_loop_callback = true;
			printf("container_loop_callback_xlated_errno=%d\n", err);
			if (!err) {
				zero_count = xlated_stack_zero_count(xlated,
								     xlated_cnt);
				printf("container_loop_callback_zero_init_count=%d\n",
				       zero_count);
			}
			break;
		case XLATED_FD_MAX_STACK:
			if (seen_max_stack && !first_err)
				first_err = EPROTO;
			seen_max_stack = true;
			printf("container_var_stack_max_xlated_errno=%d\n", err);
			if (!err) {
				has_nospec = xlated_has_nospec_stack_add(xlated,
									 xlated_cnt);
				zero_count = xlated_stack_zero_count(xlated,
								     xlated_cnt);
				printf("container_var_stack_max_nospec=%d\n",
				       has_nospec);
				printf("container_var_stack_max_zero_init_count=%d\n",
				       zero_count);
			}
			break;
		default:
			if (!first_err)
				first_err = EPROTO;
			break;
		}

		if (err && !first_err)
			first_err = err;
		free(xlated);
		close(prog_fd);
	}

	if (ret < 0 && !first_err)
		first_err = -ret;
	if ((!seen_var_stack || !seen_loop_callback || !seen_max_stack) &&
	    !first_err)
		first_err = EPROTO;
	printf("host_xlated_receive_errno=%d\n", first_err);
	return first_err;
}

static const struct bpf_insn sysctl_name_initialized[] = {
	BPF_ST_MEM(BPF_DW, BPF_REG_FP, -16, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_FP, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16),
	BPF_MOV64_IMM(BPF_REG_3, 16),
	BPF_MOV64_IMM(BPF_REG_4, BPF_F_SYSCTL_BASE_NAME),
	BPF_EMIT_CALL(BPF_FUNC_sysctl_get_name),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
};

static const struct bpf_insn sysctl_name_uninitialized[] = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16),
	BPF_MOV64_IMM(BPF_REG_3, 16),
	BPF_MOV64_IMM(BPF_REG_4, BPF_F_SYSCTL_BASE_NAME),
	BPF_EMIT_CALL(BPF_FUNC_sysctl_get_name),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
};

static const struct bpf_insn sysctl_set_new_value[] = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_MOV64_IMM(BPF_REG_3, 1),
	BPF_EMIT_CALL(BPF_FUNC_sysctl_set_new_value),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
};

static const struct bpf_insn cgroup_direct_table_helper[] = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_EMIT_CALL(BPF_FUNC_skb_ancestor_cgroup_id),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
};

static const struct bpf_insn cgroup_allowed_helper[] = {
	BPF_EMIT_CALL(BPF_FUNC_get_current_cgroup_id),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
};

static const struct bpf_insn cgroup_skb_allow[] = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
};

/*
 * Reach one variable stack ADD with two different verifier bounds, then read
 * at every direct BPF width. The translated program must use BPF_NOSPEC
 * immediately before the ADD instead of merging the path-specific ALU masks.
 */
static const struct bpf_insn sysctl_var_stack_reads[] = {
	/*  0 */ BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	/*  1 */ BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	/*  2 */ BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -64),
	/*  3 */ BPF_MOV64_IMM(BPF_REG_3, 32),
	/*  4 */ BPF_MOV64_IMM(BPF_REG_4, BPF_F_SYSCTL_BASE_NAME),
	/*  5 */ BPF_EMIT_CALL(BPF_FUNC_sysctl_get_name),
	/*  6 */ BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/*  7 */ BPF_JMP_IMM(BPF_JSLT, BPF_REG_7, 0, 17),
	/*  8 */ BPF_JMP_IMM(BPF_JGT, BPF_REG_7, 15, 16),
	/*  9 */ BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, 0),
	/* 10 */ BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 2),
	/* 11 */ BPF_JMP_IMM(BPF_JGT, BPF_REG_7, 7, 13),
	/* 12 */ BPF_JMP_A(1),
	/* 13 */ BPF_JMP_IMM(BPF_JGT, BPF_REG_7, 15, 11),
	/* Keep the shared variable offset aligned for every access width. */
	/* 14 */ BPF_MOV64_REG(BPF_REG_9, BPF_REG_7),
	/* 15 */ BPF_ALU64_IMM(BPF_AND, BPF_REG_9, -8),
	/* 16 */ BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	/* 17 */ BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -64),
	/* 18 */ BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9),
	/* 19 */ BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
	/* 20 */ BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_2, 0),
	/* 21 */ BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_2, 0),
	/* 22 */ BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_2, 0),
	/* 23 */ BPF_MOV64_IMM(BPF_REG_0, 1),
	/* 24 */ BPF_EXIT_INSN(),
	/* 25 */ BPF_MOV64_IMM(BPF_REG_0, 0),
	/* 26 */ BPF_EXIT_INSN(),
};

static const struct bpf_insn sysctl_var_stack_zero_write[] = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16),
	BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, 0),
	BPF_JMP_IMM(BPF_JLE, BPF_REG_7, 7, 1),
	BPF_MOV64_IMM(BPF_REG_7, 0),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_7),
	BPF_ST_MEM(BPF_B, BPF_REG_2, 0, 0),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
};

static const struct bpf_insn sysctl_var_stack_nonzero_write[] = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16),
	BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, 0),
	BPF_JMP_IMM(BPF_JLE, BPF_REG_7, 7, 1),
	BPF_MOV64_IMM(BPF_REG_7, 0),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_7),
	BPF_ST_MEM(BPF_B, BPF_REG_2, 0, 1),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
};

static const struct bpf_insn sysctl_var_stack_out_of_bounds[] = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, 0),
	BPF_JMP_IMM(BPF_JLE, BPF_REG_7, 15, 1),
	BPF_MOV64_IMM(BPF_REG_7, 0),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_7),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 0),
	BPF_EXIT_INSN(),
};

/*
 * Force a distinct callback frame to consume zero-initialized stack through
 * bpf_loop(). The inlined loop body uses at most three stack slots in the main
 * frame; seeing all four slots through -32 in the translated program therefore
 * proves that the callback subprogram received its own zero-init prologue.
 */
static const struct bpf_insn sysctl_loop_callback_stack[] = {
	/*  0 */ BPF_MOV64_IMM(BPF_REG_1, 1),
	/*  1 */ BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW,
			      BPF_REG_2, BPF_PSEUDO_FUNC, 0, 6),
	/*  2 */ BPF_RAW_INSN(0, 0, 0, 0, 0),
	/*  3 */ BPF_MOV64_IMM(BPF_REG_3, 0),
	/*  4 */ BPF_MOV64_IMM(BPF_REG_4, 0),
	/*  5 */ BPF_EMIT_CALL(BPF_FUNC_loop),
	/*  6 */ BPF_MOV64_IMM(BPF_REG_0, 1),
	/*  7 */ BPF_EXIT_INSN(),
	/* callback */
	/*  8 */ BPF_ST_MEM(BPF_DW, BPF_REG_FP, -32, 1),
	/*  9 */ BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_FP, -24),
	/* 10 */ BPF_MOV64_IMM(BPF_REG_0, 1),
	/* 11 */ BPF_EXIT_INSN(),
};

static int create_array_map_fd(uint32_t max_entries)
{
	union bpf_attr attr = {
		.map_type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(uint32_t),
		.value_size = sizeof(uint64_t),
		.max_entries = max_entries,
	};

	return do_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int create_map_fd(enum bpf_map_type type, uint32_t value_size)
{
	union bpf_attr attr = {
		.map_type = type,
		.key_size = sizeof(uint32_t),
		.value_size = value_size,
		.max_entries = 1,
	};

	return do_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static void patch_jump(struct bpf_insn *insns, size_t from, size_t to)
{
	insns[from].off = to - from - 1;
}

static int load_var_stack_case(bool negative, bool invert_bounds,
			       int base_off, int access_off, int access_size,
			       int *prog_fd)
{
	struct bpf_insn insns[32];
	size_t fail_jumps[4];
	size_t fail_jump_cnt = 0;
	size_t fail_idx;
	size_t n = 0;
	uint8_t size_code;
	int bound_max;
	size_t i;

	switch (access_size) {
	case 1:
		size_code = BPF_B;
		break;
	case 2:
		size_code = BPF_H;
		break;
	case 4:
		size_code = BPF_W;
		break;
	case 8:
		size_code = BPF_DW;
		break;
	default:
		return EINVAL;
	}
	bound_max = 2 * access_size - 1;

	insns[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP);
	insns[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -128);
	insns[n++] = BPF_MOV64_IMM(BPF_REG_3, 64);
	insns[n++] = BPF_MOV64_IMM(BPF_REG_4, BPF_F_SYSCTL_BASE_NAME);
	insns[n++] = BPF_EMIT_CALL(BPF_FUNC_sysctl_get_name);
	insns[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);

	if (!invert_bounds) {
		fail_jumps[fail_jump_cnt++] = n;
		insns[n++] = BPF_JMP_IMM(BPF_JSLT, BPF_REG_7, 0, 0);
		fail_jumps[fail_jump_cnt++] = n;
		insns[n++] = BPF_JMP_IMM(BPF_JSGT, BPF_REG_7,
					 bound_max, 0);
	} else {
		insns[n++] = BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 0, 1);
		fail_jumps[fail_jump_cnt++] = n;
		insns[n++] = BPF_JMP_A(0);
		insns[n++] = BPF_JMP_IMM(BPF_JSLE, BPF_REG_7,
					 bound_max, 1);
		fail_jumps[fail_jump_cnt++] = n;
		insns[n++] = BPF_JMP_A(0);
	}

	/*
	 * Retain two possible offsets while aligning both to the access width.
	 * Negative cases cover {-width, 0}; positive cases cover {0, width}.
	 */
	insns[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_7, access_size);
	if (negative)
		insns[n++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_7,
					   access_size);
	insns[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP);
	insns[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, base_off);
	insns[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_7);
	insns[n++] = BPF_LDX_MEM(size_code, BPF_REG_0, BPF_REG_2,
				 access_off);
	insns[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
	insns[n++] = BPF_EXIT_INSN();
	fail_idx = n;
	insns[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[n++] = BPF_EXIT_INSN();

	for (i = 0; i < fail_jump_cnt; i++)
		patch_jump(insns, fail_jumps[i], fail_idx);

	return load_program_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
				  BPF_CGROUP_SYSCTL, insns, n, prog_fd);
}

static int load_array_key_program(int map_fd, bool bounded, uint32_t mask)
{
	struct bpf_insn bounded_insns[] = {
		BPF_EMIT_CALL(BPF_FUNC_get_current_pid_tgid),
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
		BPF_ALU64_IMM(BPF_AND, BPF_REG_7, mask),
		BPF_STX_MEM(BPF_W, BPF_REG_FP, BPF_REG_7, -8),
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	};
	struct bpf_insn constant_insns[] = {
		BPF_ST_MEM(BPF_W, BPF_REG_FP, -8, 1),
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	};

	if (bounded)
		return load_program_errno(BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
					  BPF_CGROUP_INET4_BIND,
					  bounded_insns,
					  ARRAY_SIZE(bounded_insns), NULL);

	return load_program_errno(BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
				  BPF_CGROUP_INET4_BIND,
				  constant_insns,
				  ARRAY_SIZE(constant_insns), NULL);
}

static void emit_array_key_checks(int out_fd, const char *prefix)
{
	int map_fd;
	int err;

	map_fd = create_array_map_fd(2);
	if (map_fd < 0) {
		dprintf(out_fd, "%s_array_map_errno=%d\n", prefix, errno);
		return;
	}
	dprintf(out_fd, "%s_array_map_errno=0\n", prefix);

	err = load_array_key_program(map_fd, false, 0);
	dprintf(out_fd, "%s_array_key_constant_errno=%d\n", prefix, err);

	err = load_array_key_program(map_fd, true, 1);
	dprintf(out_fd, "%s_array_key_bounded_errno=%d\n", prefix, err);

	err = load_array_key_program(map_fd, true, 3);
	dprintf(out_fd, "%s_array_key_partial_oob_errno=%d\n", prefix, err);

	close(map_fd);
}

static void emit_var_stack_matrix_checks(int out_fd)
{
	static const int widths[] = { 1, 2, 4, 8 };
	int max_stack_fd = -1;
	size_t i;
	int err;

	for (i = 0; i < ARRAY_SIZE(widths); i++) {
		int width = widths[i];
		int fd = -1;

		err = load_var_stack_case(false, false, -2 * width, 0,
					  width, NULL);
		dprintf(out_fd, "container_var_stack_pos_safe_%d_errno=%d\n",
			width, err);

		err = load_var_stack_case(false, false, -width, 0,
					  width, NULL);
		dprintf(out_fd, "container_var_stack_pos_unsafe_%d_errno=%d\n",
			width, err);

		err = load_var_stack_case(true, false,
					  -MAX_BPF_STACK + width, 0, width,
					  width == 8 ? &fd : NULL);
		dprintf(out_fd, "container_var_stack_neg_safe_%d_errno=%d\n",
			width, err);
		if (width == 8 && !err)
			max_stack_fd = fd;

		err = load_var_stack_case(true, false, -MAX_BPF_STACK, 0,
					  width, NULL);
		dprintf(out_fd, "container_var_stack_neg_unsafe_%d_errno=%d\n",
			width, err);

		err = load_var_stack_case(false, true, -2 * width, 0,
					  width, NULL);
		dprintf(out_fd, "container_var_stack_delta_safe_%d_errno=%d\n",
			width, err);

		err = load_var_stack_case(false, true, -width, 0,
					  width, NULL);
		dprintf(out_fd, "container_var_stack_delta_unsafe_%d_errno=%d\n",
			width, err);
	}

	if (max_stack_fd < 0)
		return;

	err = -xlated_program_hidden(max_stack_fd);
	dprintf(out_fd,
		"container_var_stack_max_unpriv_xlated_hidden_errno=%d\n",
		err);
	err = -send_xlated_fd(xlated_fdpass, XLATED_FD_MAX_STACK,
			      max_stack_fd);
	dprintf(out_fd, "container_var_stack_max_xlated_send_errno=%d\n",
		err);
	close(max_stack_fd);
}

static void emit_host_bpf_policy_checks(void)
{
	int err;

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
				 BPF_CGROUP_SYSCTL,
				 sysctl_name_initialized,
				 ARRAY_SIZE(sysctl_name_initialized), NULL);
	printf("host_sysctl_initialized_errno=%d\n", err);

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
				 BPF_CGROUP_SYSCTL,
				 sysctl_name_uninitialized,
				 ARRAY_SIZE(sysctl_name_uninitialized), NULL);
	printf("host_sysctl_uninitialized_errno=%d\n", err);

	emit_array_key_checks(STDOUT_FILENO, "host");
}

static void emit_container_bpf_policy_checks(int out_fd)
{
	int fd = -1;
	int err;

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
				 BPF_CGROUP_SYSCTL,
				 sysctl_name_uninitialized,
				 ARRAY_SIZE(sysctl_name_uninitialized), NULL);
	dprintf(out_fd, "container_sysctl_uninitialized_errno=%d\n", err);

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
				 BPF_CGROUP_SYSCTL,
				 sysctl_set_new_value,
				 ARRAY_SIZE(sysctl_set_new_value), NULL);
	dprintf(out_fd, "container_sysctl_set_new_value_errno=%d\n", err);

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SKB,
				 BPF_CGROUP_INET_EGRESS,
				 cgroup_direct_table_helper,
				 ARRAY_SIZE(cgroup_direct_table_helper), NULL);
	dprintf(out_fd, "container_direct_table_helper_errno=%d\n", err);

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SKB,
				 BPF_CGROUP_INET_EGRESS,
				 cgroup_allowed_helper,
				 ARRAY_SIZE(cgroup_allowed_helper), NULL);
	dprintf(out_fd, "container_allowed_helper_errno=%d\n", err);

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
				 BPF_CGROUP_SYSCTL,
				 sysctl_var_stack_reads,
				 ARRAY_SIZE(sysctl_var_stack_reads), &fd);
	dprintf(out_fd, "container_var_stack_reads_errno=%d\n", err);
	if (!err) {
		err = -xlated_program_hidden(fd);
		dprintf(out_fd,
			"container_var_stack_unpriv_xlated_hidden_errno=%d\n",
			err);
		err = -send_xlated_fd(xlated_fdpass, XLATED_FD_VAR_STACK, fd);
		dprintf(out_fd, "container_var_stack_xlated_send_errno=%d\n",
			err);
		close(fd);
		fd = -1;
	}

	err = load_program_with_func_info_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
						BPF_CGROUP_SYSCTL,
						sysctl_loop_callback_stack,
						ARRAY_SIZE(sysctl_loop_callback_stack),
						8, &fd);
	dprintf(out_fd, "container_loop_callback_errno=%d\n", err);
	if (!err) {
		err = -xlated_program_hidden(fd);
		dprintf(out_fd,
			"container_loop_callback_unpriv_xlated_hidden_errno=%d\n",
			err);
		err = -send_xlated_fd(xlated_fdpass,
				      XLATED_FD_LOOP_CALLBACK, fd);
		dprintf(out_fd, "container_loop_callback_xlated_send_errno=%d\n",
			err);
		close(fd);
		fd = -1;
	}

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
				 BPF_CGROUP_SYSCTL,
				 sysctl_var_stack_zero_write,
				 ARRAY_SIZE(sysctl_var_stack_zero_write), NULL);
	dprintf(out_fd, "container_var_stack_zero_write_errno=%d\n", err);

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
				 BPF_CGROUP_SYSCTL,
				 sysctl_var_stack_nonzero_write,
				 ARRAY_SIZE(sysctl_var_stack_nonzero_write), NULL);
	dprintf(out_fd, "container_var_stack_nonzero_write_errno=%d\n", err);

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SYSCTL,
				 BPF_CGROUP_SYSCTL,
				 sysctl_var_stack_out_of_bounds,
				 ARRAY_SIZE(sysctl_var_stack_out_of_bounds), NULL);
	dprintf(out_fd, "container_var_stack_out_of_bounds_errno=%d\n", err);

	emit_var_stack_matrix_checks(out_fd);
	emit_array_key_checks(out_fd, "container");
}

static void
emit_container_libbpf_probe_checks(int out_fd,
				   const struct cgroup_fixture *fixture)
{
	static const struct bpf_insn zero_return[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	static const struct bpf_insn nonzero_return[] = {
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	};
	struct bpf_insn global_data[] = {
		BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1,
			     BPF_PSEUDO_MAP_VALUE, 0, 0),
		BPF_RAW_INSN(0, 0, 0, 0, 16),
		BPF_ST_MEM(BPF_DW, BPF_REG_1, 0, 42),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_array_fd = -1;
	int global_map_fd = -1;
	int ordinary_map_fd = -1;
	int global_fd = -1;
	int named_fd = -1;
	int probe_fd = -1;
	int cleanup_err = 0;
	int fields;
	int err;

	err = load_libbpf_probe_errno(BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
				      BPF_CGROUP_INET4_CONNECT,
				      zero_return, ARRAY_SIZE(zero_return),
				      NULL, "GPL", 0, &probe_fd);
	dprintf(out_fd, "container_libbpf_probe_load_errno=%d\n", err);
	if (err)
		goto out;

	err = load_libbpf_probe_errno(BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
				      BPF_CGROUP_INET4_CONNECT,
				      nonzero_return,
				      ARRAY_SIZE(nonzero_return),
				      NULL, "GPL", 0, NULL);
	dprintf(out_fd, "container_libbpf_probe_nonprobe_errno=%d\n", err);

	err = load_libbpf_probe_errno(BPF_PROG_TYPE_SOCKET_FILTER, 0,
				      zero_return, ARRAY_SIZE(zero_return),
				      "libbpf_nametest", "GPL", 0,
				      &named_fd);
	dprintf(out_fd, "container_libbpf_probe_name_load_errno=%d\n", err);

	err = load_libbpf_probe_errno(BPF_PROG_TYPE_SOCKET_FILTER, 0,
				      zero_return, ARRAY_SIZE(zero_return),
				      "not_libbpf", "GPL", 0, NULL);
	dprintf(out_fd, "container_libbpf_probe_bad_name_errno=%d\n", err);

	err = load_libbpf_probe_errno(BPF_PROG_TYPE_SOCKET_FILTER, 0,
				      zero_return, ARRAY_SIZE(zero_return),
				      NULL, "MIT", 0, NULL);
	dprintf(out_fd, "container_libbpf_probe_bad_license_errno=%d\n", err);

	err = load_libbpf_probe_errno(BPF_PROG_TYPE_SOCKET_FILTER, 0,
				      zero_return, ARRAY_SIZE(zero_return),
				      NULL, "GPL", 1, NULL);
	dprintf(out_fd, "container_libbpf_probe_metadata_errno=%d\n", err);

	err = create_cgroup_link_errno(probe_fd, -1,
				       BPF_CGROUP_INET4_CONNECT);
	dprintf(out_fd, "container_libbpf_probe_invalid_link_errno=%d\n", err);

	err = create_cgroup_link_errno(probe_fd, fixture->container_fd,
				       BPF_CGROUP_INET4_CONNECT);
	dprintf(out_fd, "container_libbpf_probe_valid_link_errno=%d\n", err);

	err = prog_info_errno(probe_fd);
	dprintf(out_fd, "container_libbpf_probe_info_errno=%d\n", err);

	err = prog_test_run_errno(probe_fd);
	dprintf(out_fd, "container_libbpf_probe_test_run_errno=%d\n", err);

	err = attach_program_errno(probe_fd, fixture->container_fd,
				   BPF_CGROUP_INET4_CONNECT, 0);
	dprintf(out_fd, "container_libbpf_probe_attach_errno=%d\n", err);

	err = prog_pin_errno(probe_fd);
	dprintf(out_fd, "container_libbpf_probe_pin_errno=%d\n", err);

	ordinary_map_fd = create_map_fd(BPF_MAP_TYPE_ARRAY, sizeof(uint64_t));
	err = ordinary_map_fd < 0 ? errno : 0;
	dprintf(out_fd, "container_libbpf_probe_map_create_errno=%d\n", err);
	if (ordinary_map_fd >= 0) {
		err = prog_bind_map_errno(probe_fd, ordinary_map_fd);
		dprintf(out_fd, "container_libbpf_probe_bind_map_errno=%d\n",
			err);
	}

	err = prog_raw_tracepoint_errno(probe_fd);
	dprintf(out_fd, "container_libbpf_probe_raw_tracepoint_errno=%d\n",
		err);

	prog_array_fd = create_map_fd(BPF_MAP_TYPE_PROG_ARRAY,
				      sizeof(uint32_t));
	err = prog_array_fd < 0 ? errno : 0;
	dprintf(out_fd, "container_libbpf_probe_prog_array_create_errno=%d\n",
		err);
	if (prog_array_fd >= 0) {
		err = prog_array_update_errno(prog_array_fd, probe_fd);
		dprintf(out_fd,
			"container_libbpf_probe_prog_array_update_errno=%d\n",
			err);
	}

	err = prog_stream_read_errno(probe_fd);
	dprintf(out_fd, "container_libbpf_probe_stream_read_errno=%d\n",
		err);

	fields = prog_fdinfo_fields(probe_fd);
	err = fields < 0 ? -fields : 0;
	dprintf(out_fd, "container_libbpf_probe_fdinfo_errno=%d\n", err);
	dprintf(out_fd, "container_libbpf_probe_fdinfo_fields=%d\n",
		fields < 0 ? -1 : fields);

	global_data[0].imm = -1;
	err = load_libbpf_probe_errno(BPF_PROG_TYPE_SOCKET_FILTER, 0,
				      global_data, ARRAY_SIZE(global_data),
				      NULL, "GPL", 0, NULL);
	dprintf(out_fd, "container_libbpf_probe_bad_map_fd_errno=%d\n", err);

	global_map_fd = create_map_fd(BPF_MAP_TYPE_ARRAY, 32);
	err = global_map_fd < 0 ? errno : 0;
	dprintf(out_fd, "container_libbpf_probe_global_map_create_errno=%d\n",
		err);
	if (global_map_fd >= 0) {
		global_data[0].imm = global_map_fd;
		err = load_libbpf_probe_errno(BPF_PROG_TYPE_SOCKET_FILTER, 0,
					      global_data,
					      ARRAY_SIZE(global_data),
					      NULL, "GPL", 0, &global_fd);
		dprintf(out_fd,
			"container_libbpf_probe_global_load_errno=%d\n", err);
	}

out:
	if (global_fd >= 0 && close(global_fd) && !cleanup_err)
		cleanup_err = errno;
	if (global_map_fd >= 0 && close(global_map_fd) && !cleanup_err)
		cleanup_err = errno;
	if (prog_array_fd >= 0 && close(prog_array_fd) && !cleanup_err)
		cleanup_err = errno;
	if (ordinary_map_fd >= 0 && close(ordinary_map_fd) && !cleanup_err)
		cleanup_err = errno;
	if (named_fd >= 0 && close(named_fd) && !cleanup_err)
		cleanup_err = errno;
	if (probe_fd >= 0 && close(probe_fd) && !cleanup_err)
		cleanup_err = errno;
	dprintf(out_fd, "container_libbpf_probe_cleanup_errno=%d\n",
		cleanup_err);
}

static void keep_first_error(int *first, int err)
{
	if (err && !*first)
		*first = err;
}

static void emit_container_cgroup_checks(int out_fd,
					 const struct cgroup_fixture *fixture)
{
	uint32_t direct_ids[4] = {};
	uint32_t effective_ids[4] = {};
	uint32_t short_ids[1] = {};
	uint32_t prog1_id = 0;
	uint32_t prog2_id = 0;
	uint32_t cnt;
	bool prog1_attached = false;
	bool prog2_attached = false;
	bool ingress_attached = false;
	int ingress_fd = -1;
	int prog1_fd = -1;
	int prog2_fd = -1;
	int cleanup_err = 0;
	int err;

	cnt = 0;
	err = query_programs_errno(fixture->container_fd,
				   BPF_CGROUP_INET4_CONNECT, 0, NULL, &cnt);
	dprintf(out_fd, "container_cgroup_query_disallowed_errno=%d\n", err);

	cnt = 0;
	err = query_programs_errno(fixture->peer_fd,
				   BPF_CGROUP_INET_EGRESS, 0, NULL, &cnt);
	dprintf(out_fd, "container_cgroup_query_peer_errno=%d\n", err);

	cnt = 0;
	err = query_programs_errno(fixture->root_fd,
				   BPF_CGROUP_INET_EGRESS, 0, NULL, &cnt);
	dprintf(out_fd, "container_cgroup_query_host_errno=%d\n", err);

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SKB,
				 BPF_CGROUP_INET_EGRESS,
				 cgroup_skb_allow,
				 ARRAY_SIZE(cgroup_skb_allow), &prog1_fd);
	dprintf(out_fd, "container_cgroup_prog1_load_errno=%d\n", err);
	if (!err)
		err = get_program_id(prog1_fd, &prog1_id);
	dprintf(out_fd, "container_cgroup_prog1_id_errno=%d\n", err);
	dprintf(out_fd, "container_cgroup_prog1_id=%u\n", prog1_id);

	if (prog1_fd >= 0)
		err = attach_program_errno(prog1_fd, fixture->container_fd,
					   BPF_CGROUP_INET_EGRESS,
					   BPF_F_ALLOW_MULTI);
	else
		err = EBADF;
	dprintf(out_fd, "container_cgroup_prog1_attach_errno=%d\n", err);
	prog1_attached = !err;

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SKB,
				 BPF_CGROUP_INET_EGRESS,
				 cgroup_skb_allow,
				 ARRAY_SIZE(cgroup_skb_allow), &prog2_fd);
	dprintf(out_fd, "container_cgroup_prog2_load_errno=%d\n", err);
	if (!err)
		err = get_program_id(prog2_fd, &prog2_id);
	dprintf(out_fd, "container_cgroup_prog2_id_errno=%d\n", err);
	dprintf(out_fd, "container_cgroup_prog2_id=%u\n", prog2_id);

	if (prog2_fd >= 0)
		err = attach_program_errno(prog2_fd, fixture->container_fd,
					   BPF_CGROUP_INET_EGRESS,
					   BPF_F_ALLOW_MULTI);
	else
		err = EBADF;
	dprintf(out_fd, "container_cgroup_prog2_attach_errno=%d\n", err);
	prog2_attached = !err;

	cnt = ARRAY_SIZE(direct_ids);
	err = query_programs_errno(fixture->container_fd,
				   BPF_CGROUP_INET_EGRESS, 0,
				   direct_ids, &cnt);
	dprintf(out_fd, "container_cgroup_query_direct_errno=%d\n", err);
	dprintf(out_fd, "container_cgroup_query_direct_count=%u\n", cnt);
	dprintf(out_fd, "container_cgroup_query_direct_id0=%u\n",
		direct_ids[0]);
	dprintf(out_fd, "container_cgroup_query_direct_id1=%u\n",
		direct_ids[1]);

	cnt = ARRAY_SIZE(effective_ids);
	err = query_programs_errno(fixture->container_fd,
				   BPF_CGROUP_INET_EGRESS,
				   BPF_F_QUERY_EFFECTIVE,
				   effective_ids, &cnt);
	dprintf(out_fd, "container_cgroup_query_effective_errno=%d\n", err);
	dprintf(out_fd, "container_cgroup_query_effective_count=%u\n", cnt);
	dprintf(out_fd, "container_cgroup_query_effective_id0=%u\n",
		effective_ids[0]);
	dprintf(out_fd, "container_cgroup_query_effective_id1=%u\n",
		effective_ids[1]);

	cnt = ARRAY_SIZE(short_ids);
	short_ids[0] = 0;
	err = query_programs_errno(fixture->container_fd,
				   BPF_CGROUP_INET_EGRESS, 0,
				   short_ids, &cnt);
	dprintf(out_fd, "container_cgroup_query_direct_short_errno=%d\n", err);
	dprintf(out_fd, "container_cgroup_query_direct_short_count=%u\n", cnt);
	dprintf(out_fd, "container_cgroup_query_direct_short_id0=%u\n",
		short_ids[0]);

	cnt = ARRAY_SIZE(short_ids);
	short_ids[0] = 0;
	err = query_programs_errno(fixture->container_fd,
				   BPF_CGROUP_INET_EGRESS,
				   BPF_F_QUERY_EFFECTIVE,
				   short_ids, &cnt);
	dprintf(out_fd,
		"container_cgroup_query_effective_short_errno=%d\n", err);
	dprintf(out_fd,
		"container_cgroup_query_effective_short_count=%u\n", cnt);
	dprintf(out_fd, "container_cgroup_query_effective_short_id0=%u\n",
		short_ids[0]);

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SKB,
				 BPF_CGROUP_INET_INGRESS,
				 cgroup_skb_allow,
				 ARRAY_SIZE(cgroup_skb_allow), &ingress_fd);
	dprintf(out_fd, "container_cgroup_ingress_load_errno=%d\n", err);
	if (ingress_fd >= 0)
		err = attach_program_errno(ingress_fd, fixture->container_fd,
					   BPF_CGROUP_INET_INGRESS, 0);
	else
		err = EBADF;
	dprintf(out_fd, "container_cgroup_ingress_attach_errno=%d\n", err);
	ingress_attached = !err;

	if (ingress_attached)
		err = detach_program_errno(0, fixture->container_fd,
					   BPF_CGROUP_INET_INGRESS);
	else
		err = ENOENT;
	dprintf(out_fd, "container_cgroup_detach_fdless_errno=%d\n", err);
	if (!err)
		ingress_attached = false;

	if (ingress_fd >= 0)
		err = attach_program_errno(ingress_fd, fixture->container_fd,
					   BPF_CGROUP_INET_INGRESS, 0);
	else
		err = EBADF;
	dprintf(out_fd, "container_cgroup_ingress_reattach_errno=%d\n", err);
	ingress_attached = !err;

	if (ingress_attached)
		err = detach_program_errno(-1, fixture->container_fd,
					   BPF_CGROUP_INET_INGRESS);
	else
		err = ENOENT;
	dprintf(out_fd, "container_cgroup_detach_invalid_fd_errno=%d\n", err);
	if (!err)
		ingress_attached = false;

	err = detach_program_errno(0, fixture->container_fd,
				   BPF_CGROUP_INET4_CONNECT);
	dprintf(out_fd, "container_cgroup_detach_disallowed_errno=%d\n", err);

	err = detach_program_errno(fixture->host_prog_fd,
				   fixture->container_fd,
				   BPF_CGROUP_INET_EGRESS);
	dprintf(out_fd, "container_cgroup_detach_foreign_fd_errno=%d\n", err);

	err = detach_program_errno(0, fixture->peer_fd,
				   BPF_CGROUP_INET_INGRESS);
	dprintf(out_fd, "container_cgroup_detach_peer_fdless_errno=%d\n", err);

	err = detach_program_errno(0, fixture->root_fd,
				   BPF_CGROUP_INET_INGRESS);
	dprintf(out_fd, "container_cgroup_detach_host_fdless_errno=%d\n", err);

	if (ingress_attached)
		keep_first_error(&cleanup_err,
				 detach_program_errno(ingress_fd,
						      fixture->container_fd,
						      BPF_CGROUP_INET_INGRESS));
	if (prog2_attached)
		keep_first_error(&cleanup_err,
				 detach_program_errno(prog2_fd,
						      fixture->container_fd,
						      BPF_CGROUP_INET_EGRESS));
	if (prog1_attached)
		keep_first_error(&cleanup_err,
				 detach_program_errno(prog1_fd,
						      fixture->container_fd,
						      BPF_CGROUP_INET_EGRESS));
	if (ingress_fd >= 0)
		close(ingress_fd);
	if (prog2_fd >= 0)
		close(prog2_fd);
	if (prog1_fd >= 0)
		close(prog1_fd);
	dprintf(out_fd, "container_cgroup_cleanup_errno=%d\n", cleanup_err);
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

static void init_cgroup_fixture(struct cgroup_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->root_fd = -1;
	fixture->container_fd = -1;
	fixture->peer_fd = -1;
	fixture->host_prog_fd = -1;
}

static int append_path(char *dst, size_t dst_size, const char *base,
		       const char *suffix)
{
	size_t base_len = strlen(base);
	size_t suffix_len = strlen(suffix);

	if (base_len >= dst_size || suffix_len >= dst_size - base_len)
		return ENAMETOOLONG;
	memcpy(dst, base, base_len);
	memcpy(dst + base_len, suffix, suffix_len + 1);
	return 0;
}

static int remove_cgroup_dir(const char *path, bool created)
{
	if (!created || !path[0])
		return 0;
	if (!rmdir(path) || errno == ENOENT)
		return 0;
	return errno;
}

static int destroy_cgroup_fixture(struct cgroup_fixture *fixture)
{
	int err = 0;
	int ret;

	if (fixture->host_prog_attached) {
		ret = detach_program_errno(fixture->host_prog_fd,
					   fixture->container_fd,
					   BPF_CGROUP_INET_EGRESS);
		if (ret && !err)
			err = ret;
		fixture->host_prog_attached = false;
	}

	if (fixture->host_prog_fd >= 0)
		close(fixture->host_prog_fd);
	if (fixture->peer_fd >= 0)
		close(fixture->peer_fd);
	if (fixture->container_fd >= 0)
		close(fixture->container_fd);
	if (fixture->root_fd >= 0)
		close(fixture->root_fd);
	fixture->host_prog_fd = -1;
	fixture->peer_fd = -1;
	fixture->container_fd = -1;
	fixture->root_fd = -1;

	ret = remove_cgroup_dir(fixture->peer_path, fixture->peer_created);
	if (ret && !err)
		err = ret;
	ret = remove_cgroup_dir(fixture->container_path,
				fixture->container_created);
	if (ret && !err)
		err = ret;
	ret = remove_cgroup_dir(fixture->base_path, fixture->base_created);
	if (ret && !err)
		err = ret;

	return err;
}

static int setup_cgroup_fixture(struct cgroup_fixture *fixture)
{
	char cgroup2_marker[PATH_MAX];
	int err;

	init_cgroup_fixture(fixture);
	snprintf(cgroup2_marker, sizeof(cgroup2_marker),
		 "/sys/fs/cgroup/cgroup.controllers");
	if (access(cgroup2_marker, F_OK))
		return ENODEV;

	snprintf(fixture->base_path, sizeof(fixture->base_path),
		 "/sys/fs/cgroup/vpsadminos-bpf-userns-%ld", (long)getpid());
	err = append_path(fixture->container_path,
			  sizeof(fixture->container_path),
			  fixture->base_path, "/container");
	if (err)
		return err;
	err = append_path(fixture->peer_path, sizeof(fixture->peer_path),
			  fixture->base_path, "/peer");
	if (err)
		return err;

	if (mkdir(fixture->base_path, 0755))
		return errno;
	fixture->base_created = true;
	if (mkdir(fixture->container_path, 0755)) {
		err = errno;
		goto fail;
	}
	fixture->container_created = true;
	if (mkdir(fixture->peer_path, 0755)) {
		err = errno;
		goto fail;
	}
	fixture->peer_created = true;

	fixture->root_fd = open("/sys/fs/cgroup",
				O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fixture->root_fd < 0) {
		err = errno;
		goto fail;
	}
	fixture->container_fd = open(fixture->container_path,
				     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fixture->container_fd < 0) {
		err = errno;
		goto fail;
	}
	fixture->peer_fd = open(fixture->peer_path,
				O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fixture->peer_fd < 0) {
		err = errno;
		goto fail;
	}

	err = load_program_errno(BPF_PROG_TYPE_CGROUP_SKB,
				 BPF_CGROUP_INET_EGRESS,
				 cgroup_skb_allow,
				 ARRAY_SIZE(cgroup_skb_allow),
				 &fixture->host_prog_fd);
	if (err)
		goto fail;
	err = attach_program_errno(fixture->host_prog_fd,
				   fixture->container_fd,
				   BPF_CGROUP_INET_EGRESS,
				   BPF_F_ALLOW_MULTI);
	if (err)
		goto fail;
	fixture->host_prog_attached = true;
	return 0;

fail:
	destroy_cgroup_fixture(fixture);
	return err;
}

static int move_pid_to_cgroup(const struct cgroup_fixture *fixture, pid_t pid)
{
	char procs_path[PATH_MAX];
	char pid_buf[32];
	int err;

	err = append_path(procs_path, sizeof(procs_path),
			  fixture->container_path, "/cgroup.procs");
	if (err)
		return err;
	snprintf(pid_buf, sizeof(pid_buf), "%d\n", pid);
	if (write_file(procs_path, pid_buf))
		return errno;
	return 0;
}

static int map_child_userns(pid_t pid)
{
	char path[PATH_MAX];
	char map[64];
	uid_t uid = getuid();
	gid_t gid = getgid();

	snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
	snprintf(map, sizeof(map), "0 %u 1\n", uid);
	if (write_file(path, map) < 0)
		return errno;

	snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
	if (write_file(path, "deny") < 0 && errno != ENOENT)
		return errno;

	snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
	snprintf(map, sizeof(map), "0 %u 1\n", gid);
	if (write_file(path, map) < 0)
		return errno;

	return 0;
}

static int map_self_userns(uid_t parent_uid)
{
	char map[64];

	snprintf(map, sizeof(map), "0 %u 1\n", parent_uid);
	if (write_file("/proc/self/uid_map", map) < 0)
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

static int nested_userns_child(struct child_cfg *cfg, int readyfd, int gofd)
{
	uid_t parent_uid = getuid();
	int err;

	err = unshare(CLONE_NEWUSER) < 0 ? errno : 0;
	if (!err)
		err = map_self_userns(parent_uid);
	if (write(readyfd, &err, sizeof(err)) != (ssize_t)sizeof(err)) {
		close(readyfd);
		close(gofd);
		return 1;
	}
	close(readyfd);

	if (err) {
		dprintf(cfg->pipefd, "nested_userns_errno=%d\n", err);
		close(gofd);
		return 1;
	}

	err = wait_for_parent_mapping(gofd);
	if (err) {
		dprintf(cfg->pipefd, "nested_sync_errno=%d\n", err);
		return 1;
	}

	if (setresuid(0, 0, 0) < 0) {
		dprintf(cfg->pipefd, "nested_userns_errno=%d\n", errno);
		return 1;
	}

	dprintf(cfg->pipefd, "nested_userns_errno=0\n");
	if (emit_ns_links(cfg->pipefd, "nested")) {
		dprintf(cfg->pipefd, "nested_errno=%d\n", errno);
		return 1;
	}

	err = kallsyms_has_symbol(cfg->symbol);
	dprintf(cfg->pipefd, "nested_kallsyms_has_symbol=%d\n", err);

	err = create_array_map_errno();
	dprintf(cfg->pipefd, "nested_bpf_errno=%d\n", err);
	{
		uint32_t cnt = 0;

		err = query_programs_errno(cfg->cgroup->container_fd,
					   BPF_CGROUP_INET_EGRESS,
					   0, NULL, &cnt);
		dprintf(cfg->pipefd, "nested_cgroup_query_errno=%d\n", err);

		err = detach_program_errno(0, cfg->cgroup->container_fd,
					   BPF_CGROUP_INET_INGRESS);
		dprintf(cfg->pipefd, "nested_cgroup_detach_errno=%d\n", err);
	}
	return 0;
}

static int run_nested_userns(struct child_cfg *cfg)
{
	int readyfd[2];
	int gofd[2];
	pid_t pid;
	int child_err;
	int status;
	ssize_t n;
	int err;

	if (pipe(readyfd) < 0)
		return errno;
	if (pipe(gofd) < 0) {
		err = errno;
		close(readyfd[0]);
		close(readyfd[1]);
		return err;
	}

	pid = fork();
	if (pid < 0) {
		err = errno;
		close(readyfd[0]);
		close(readyfd[1]);
		close(gofd[0]);
		close(gofd[1]);
		return err;
	}

	if (pid == 0) {
		close(readyfd[0]);
		close(gofd[1]);
		err = nested_userns_child(cfg, readyfd[1], gofd[0]);
		close(cfg->pipefd);
		_exit(err ? EXIT_FAILURE : EXIT_SUCCESS);
	}

	close(readyfd[1]);
	close(gofd[0]);
	n = read(readyfd[0], &child_err, sizeof(child_err));
	close(readyfd[0]);
	if (n != (ssize_t)sizeof(child_err)) {
		err = n < 0 ? errno : EIO;
		close(gofd[1]);
		waitpid(pid, &status, 0);
		return err;
	}
	if (child_err) {
		close(gofd[1]);
		waitpid(pid, &status, 0);
		return child_err;
	}

	if (write(gofd[1], "x", 1) != 1) {
		err = errno;
		close(gofd[1]);
		waitpid(pid, &status, 0);
		return err;
	}
	close(gofd[1]);

	if (waitpid(pid, &status, 0) < 0)
		return errno;
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		return EXIT_FAILURE;

	return 0;
}

static int child_main(void *arg)
{
	struct child_cfg *cfg = arg;
	int err;

	close(cfg->parent_read_fd);
	close(cfg->sync_write_fd);
	close(cfg->parent_fdpass);
	err = wait_for_parent_mapping(cfg->syncfd);
	if (err) {
		dprintf(cfg->pipefd, "child_sync_errno=%d\n", err);
		close(cfg->pipefd);
		return 1;
	}

	if (unshare(CLONE_NEWCGROUP) < 0) {
		err = errno;
		dprintf(cfg->pipefd, "child_cgroupns_errno=%d\n", err);
		close(cfg->pipefd);
		return 1;
	}
	dprintf(cfg->pipefd, "child_cgroupns_errno=0\n");

	if (emit_ns_links(cfg->pipefd, "child")) {
		err = errno;
		dprintf(cfg->pipefd, "child_errno=%d\n", err);
		close(cfg->pipefd);
		return 1;
	}

	err = kallsyms_has_symbol(cfg->symbol);
	dprintf(cfg->pipefd, "child_kallsyms_has_symbol=%d\n", err);

	err = drop_and_verify_bpf_admin_caps();
	dprintf(cfg->pipefd, "first_level_cap_drop_errno=%d\n", err);
	if (err) {
		close(cfg->pipefd);
		return 1;
	}

	err = create_array_map_errno();
	dprintf(cfg->pipefd, "first_level_bpf_errno=%d\n", err);
	xlated_fdpass = cfg->fdpass;
	emit_container_bpf_policy_checks(cfg->pipefd);
	emit_container_libbpf_probe_checks(cfg->pipefd, cfg->cgroup);
	emit_container_cgroup_checks(cfg->pipefd, cfg->cgroup);

	err = run_nested_userns(cfg);
	if (err) {
		close(cfg->pipefd);
		return 1;
	}
	close(cfg->fdpass);
	close(cfg->pipefd);
	return 0;
}

int main(int argc, char **argv)
{
	struct child_cfg cfg = { .pipefd = -1 };
	struct cgroup_fixture cgroup;
	const char *syslog_name = "traceBpf";
	const char *symbol = "copy_process";
	char *stack;
	int fdpass[2];
	int pipefd[2];
	int syncfd[2];
	pid_t pid;
	int status;
	char buf[32768];
	int cleanup_err;
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

	emit_host_bpf_policy_checks();

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
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fdpass) < 0) {
		perror("fd socketpair");
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}
	if (pipe(syncfd) < 0) {
		perror("sync pipe");
		close(pipefd[0]);
		close(pipefd[1]);
		close(fdpass[0]);
		close(fdpass[1]);
		return 1;
	}

	cfg.pipefd = pipefd[1];
	cfg.parent_read_fd = pipefd[0];
	cfg.syncfd = syncfd[0];
	cfg.sync_write_fd = syncfd[1];
	cfg.fdpass = fdpass[1];
	cfg.parent_fdpass = fdpass[0];
	cfg.cgroup = &cgroup;
	stack = malloc(STACK_SIZE);
	if (!stack) {
		perror("malloc");
		close(pipefd[0]);
		close(pipefd[1]);
		close(syncfd[0]);
		close(syncfd[1]);
		close(fdpass[0]);
		close(fdpass[1]);
		return 1;
	}

	i = setup_cgroup_fixture(&cgroup);
	printf("host_cgroup_fixture_errno=%d\n", i);
	if (i) {
		close(pipefd[0]);
		close(pipefd[1]);
		close(syncfd[0]);
		close(syncfd[1]);
		close(fdpass[0]);
		close(fdpass[1]);
		free(stack);
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
		close(fdpass[0]);
		close(fdpass[1]);
		destroy_cgroup_fixture(&cgroup);
		free(stack);
		return 1;
	}

	close_fd(&pipefd[1]);
	close_fd(&syncfd[0]);
	close_fd(&fdpass[1]);
	i = map_child_userns(pid);
	if (i) {
		printf("map_child_errno=%d\n", i);
		goto fail_child;
	}
	i = move_pid_to_cgroup(&cgroup, pid);
	if (i) {
		printf("move_child_cgroup_errno=%d\n", i);
		goto fail_child;
	}
	printf("move_child_cgroup_errno=0\n");
	do {
		n = write(syncfd[1], "x", 1);
	} while (n < 0 && errno == EINTR);
	if (n != 1) {
		perror("sync write");
		goto fail_child;
	}
	close_fd(&syncfd[1]);

	for (n = 0; n < (ssize_t)sizeof(buf) - 1;) {
		ssize_t r;

		r = read(pipefd[0], buf + n, sizeof(buf) - 1 - n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			n = -1;
			break;
		}
		if (r == 0)
			break;
		n += r;
	}
	if (n < 0) {
		perror("read");
		goto fail_child;
	}
	buf[n] = '\0';
	close_fd(&pipefd[0]);
	printf("%s", buf);

	i = emit_host_xlated_checks(fdpass[0]);
	close_fd(&fdpass[0]);
	if (i)
		goto fail_child;

	i = waitpid_exact(pid, &status);
	if (i) {
		errno = i;
		perror("waitpid");
		goto fail_child;
	}

	cleanup_err = destroy_cgroup_fixture(&cgroup);
	printf("host_cgroup_cleanup_errno=%d\n", cleanup_err);
	free(stack);
	if (cleanup_err || !WIFEXITED(status))
		return 1;

	return WEXITSTATUS(status);

fail_child:
	close_fd(&fdpass[0]);
	close_fd(&fdpass[1]);
	i = abort_child(pid, &pipefd[0], &syncfd[1]);
	if (i)
		fprintf(stderr, "child cleanup failed: %s\n", strerror(i));
	cleanup_err = destroy_cgroup_fixture(&cgroup);
	printf("host_cgroup_cleanup_errno=%d\n", cleanup_err);
	free(stack);
	return 1;
}
