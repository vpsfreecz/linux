#include <linux/bpf.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/namei.h>
#include <linux/user_namespace.h>
#include <linux/security.h>
#include <linux/tracing_namespace.h>
#include "../trace/trace_btf.h"

static bool bpf_ns_capable(struct user_namespace *ns, int cap)
{
	return ns_capable(ns, cap) || (cap != CAP_SYS_ADMIN && ns_capable(ns, CAP_SYS_ADMIN));
}

bool bpf_token_is_container(const struct bpf_token *token)
{
	return token && (token->flags & BPF_TOKEN_F_CONTAINER);
}

static bool bpf_token_is_internal(const struct bpf_token *token)
{
	return token && (token->flags & BPF_TOKEN_F_INTERNAL);
}

bool bpf_token_same_container_domain(const struct bpf_token *a,
					 const struct bpf_token *b)
{
	if (!bpf_token_is_container(a) || !bpf_token_is_container(b))
		return false;

	return a->tracing_ns && a->tracing_ns == b->tracing_ns;
}

bool bpf_token_task_match(const struct bpf_token *token,
			     const struct task_struct *task)
{
	if (!bpf_token_is_container(token))
		return true;
	if (!task || !token->tracing_ns)
		return false;

	return tracing_ns_matches_task(token->tracing_ns, task);
}

static bool bpf_token_current_container_member(void)
{
#ifdef CONFIG_TRACING_NS
	struct tracing_namespace *tns = current_tracing_ns();

	if (!tns || tns == &init_tracing_ns)
		return false;

	return tracing_ns_matches_task(tns, current);
#else
	return false;
#endif
}

/*
 * Container tracing authority is anchored to the user namespace that owns the
 * tracing boundary. A nested user namespace inside the same tracing guest must
 * not regain tracing privileges solely by becoming capable in that nested
 * namespace.
 */
static struct user_namespace *bpf_token_current_container_userns(void)
{
#ifdef CONFIG_TRACING_NS
	struct tracing_namespace *tns = current_tracing_ns();

	if (!bpf_token_current_container_member())
		return NULL;

	return tns->user_ns;
#else
	return NULL;
#endif
}

bool bpf_token_current_container_capable(int cap)
{
	struct user_namespace *userns;

	userns = bpf_token_current_container_userns();
	if (!userns)
		return false;

	return bpf_ns_capable(userns, cap);
}

/*
 * Symbol discovery is a tracing-boundary property, not a capability-only one.
 * Tasks inside the same tracing guest must not fall back to broader host-side
 * discovery surfaces merely because they dropped tracing caps or entered a
 * nested user namespace.
 */
bool bpf_token_current_restrict_tracing_symbols(void)
{
	if (!sysctl_bpf_container_tracing_enabled)
		return false;

	return bpf_token_current_container_member();
}

static bool bpf_token_allow_syscall_symbol(const char *name, const char *syscall)
{
	static const char * const prefixes[] = {
		"__x64_sys_",
		"__ia32_sys_",
		"__arm64_sys_",
		"__riscv_sys_",
		"__s390x_sys_",
		"__s390_sys_",
		"__powerpc_sys_",
		"__powerpc64_sys_",
		"__sparc_sys_",
		"__sparc64_sys_",
		"__se_sys_",
		"__do_sys_",
		"sys_",
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(prefixes); i++) {
		const char *prefix = prefixes[i];
		size_t len = strlen(prefix);

		if (!strncmp(name, prefix, len) && !strcmp(name + len, syscall))
			return true;
	}

	return false;
}

static bool bpf_token_allow_container_symbol_access_name(const char *name)
{
	static const char * const exact_symbols[] = {
		"sched_fork",
		"wake_up_new_task",
		"tcp_v4_connect",
		"tcp_v6_connect",
		"tcp_set_state",
		"tcp_close",
		"inet_csk_accept",
		"udp_recvmsg",
		"udpv6_queue_rcv_one_skb",
	};
	static const char * const syscall_names[] = {
		"open",
		"openat",
		"openat2",
		"kill",
		"tkill",
		"tgkill",
		"fork",
		"vfork",
		"clone",
		"clone3",
		"execve",
		"execveat",
		"mount",
		"umount2",
		"fsopen",
		"fsconfig",
		"fsmount",
		"move_mount",
		"open_tree",
		"mount_setattr",
		"read",
		"write",
		"pread64",
		"pwrite64",
		"stat",
		"lstat",
		"newfstatat",
		"statx",
		"connect",
		"accept",
		"accept4",
	};
	int i;

	if (!name || !*name)
		return false;

	for (i = 0; i < ARRAY_SIZE(exact_symbols); i++) {
		if (!strcmp(name, exact_symbols[i]))
			return true;
	}

	for (i = 0; i < ARRAY_SIZE(syscall_names); i++) {
		if (bpf_token_allow_syscall_symbol(name, syscall_names[i]))
			return true;
	}

	return false;
}

static bool bpf_token_allow_container_symbol_discovery_name(const char *name)
{
	const struct btf_type *proto;
	struct btf *btf;
	bool ok = false;

	if (!name || !*name)
		return false;

	proto = btf_find_func_proto(name, &btf);
	if (!proto)
		return false;

	if (btf_type_vlen(proto) <= MAX_BPF_FUNC_ARGS)
		ok = true;

	btf_put(btf);
	return ok;
}

static struct bpf_token *bpf_token_alloc_current_container(void)
{
	struct bpf_token *token;
	struct user_namespace *userns;
#ifdef CONFIG_TRACING_NS
	struct tracing_namespace *tns = current_tracing_ns();
#else
	struct tracing_namespace *tns = NULL;
#endif

	if (!bpf_token_current_container_capable(CAP_BPF) &&
	    !bpf_token_current_container_capable(CAP_PERFMON) &&
	    !bpf_token_current_container_capable(CAP_SYS_ADMIN) &&
	    !bpf_token_current_container_capable(CAP_NET_ADMIN))
		return NULL;
	userns = bpf_token_current_container_userns();
	if (!tns || !userns)
		return NULL;

	token = kzalloc(sizeof(*token), GFP_KERNEL);
	if (!token)
		return ERR_PTR(-ENOMEM);

	atomic64_set(&token->refcnt, 1);
	token->flags = BPF_TOKEN_F_CONTAINER | BPF_TOKEN_F_INTERNAL;
	token->userns = get_user_ns(userns);
	token->tracing_ns = get_tracing_ns(tns);

	return token;
}

struct bpf_token *bpf_token_get_current_container(void)
{
	return bpf_token_alloc_current_container();
}

bool bpf_token_allow_tracing_symbol(const struct bpf_token *token, const char *name)
{
	if (!bpf_token_is_container(token))
		return true;

	return bpf_token_allow_container_symbol_discovery_name(name);
}

bool bpf_token_current_allow_tracing_symbol(const char *name)
{
	if (!bpf_token_current_restrict_tracing_symbols())
		return true;

	return bpf_token_allow_container_symbol_discovery_name(name);
}

bool bpf_token_allow_tracing_symbol_accesses(const struct bpf_token *token,
				      const char *name)
{
	if (!bpf_token_is_container(token))
		return true;

	return bpf_token_allow_container_symbol_access_name(name);
}

bool bpf_token_allow_helper(const struct bpf_token *token, enum bpf_func_id func_id)
{
	if (!bpf_token_is_container(token))
		return true;

	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
	case BPF_FUNC_map_update_elem:
	case BPF_FUNC_map_delete_elem:
	case BPF_FUNC_map_push_elem:
	case BPF_FUNC_map_pop_elem:
	case BPF_FUNC_map_peek_elem:
	case BPF_FUNC_map_lookup_percpu_elem:
	case BPF_FUNC_get_prandom_u32:
	case BPF_FUNC_get_smp_processor_id:
	case BPF_FUNC_get_numa_node_id:
	case BPF_FUNC_tail_call:
	case BPF_FUNC_ktime_get_ns:
	case BPF_FUNC_ktime_get_boot_ns:
	case BPF_FUNC_ktime_get_tai_ns:
	case BPF_FUNC_jiffies64:
	case BPF_FUNC_skb_load_bytes:
	case BPF_FUNC_ringbuf_output:
	case BPF_FUNC_ringbuf_reserve:
	case BPF_FUNC_ringbuf_submit:
	case BPF_FUNC_ringbuf_discard:
	case BPF_FUNC_ringbuf_query:
	case BPF_FUNC_ringbuf_reserve_dynptr:
	case BPF_FUNC_ringbuf_submit_dynptr:
	case BPF_FUNC_ringbuf_discard_dynptr:
	case BPF_FUNC_dynptr_from_mem:
	case BPF_FUNC_dynptr_read:
	case BPF_FUNC_dynptr_write:
	case BPF_FUNC_dynptr_data:
	case BPF_FUNC_strncmp:
	case BPF_FUNC_strtol:
	case BPF_FUNC_strtoul:
	case BPF_FUNC_snprintf:
	case BPF_FUNC_loop:
	case BPF_FUNC_get_current_pid_tgid:
	case BPF_FUNC_get_current_cgroup_id:
	case BPF_FUNC_get_ns_current_pid_tgid:
	case BPF_FUNC_get_current_uid_gid:
	case BPF_FUNC_get_current_comm:
	case BPF_FUNC_get_current_task:
	case BPF_FUNC_get_current_task_btf:
	case BPF_FUNC_probe_read:
	case BPF_FUNC_probe_read_kernel:
	case BPF_FUNC_probe_read_user:
	case BPF_FUNC_probe_read_user_str:
	case BPF_FUNC_copy_from_user:
	case BPF_FUNC_perf_event_output:
	case BPF_FUNC_get_attach_cookie:
		return true;
	default:
		return false;
	}
}

bool bpf_token_capable(const struct bpf_token *token, int cap)
{
	struct user_namespace *userns;

	/* BPF token allows ns_capable() level of capabilities */
	userns = token ? token->userns : &init_user_ns;
	if (!bpf_ns_capable(userns, cap))
		return false;
	if (token && !bpf_token_is_internal(token) &&
	    security_bpf_token_capable(token, cap) < 0)
		return false;
	return true;
}

void bpf_token_inc(struct bpf_token *token)
{
	atomic64_inc(&token->refcnt);
}

static void bpf_token_free(struct bpf_token *token)
{
	if (!bpf_token_is_internal(token))
		security_bpf_token_free(token);
	put_user_ns(token->userns);
	put_tracing_ns(token->tracing_ns);
	kfree(token);
}

static void bpf_token_put_deferred(struct work_struct *work)
{
	struct bpf_token *token = container_of(work, struct bpf_token, work);

	bpf_token_free(token);
}

void bpf_token_put(struct bpf_token *token)
{
	if (!token)
		return;

	if (!atomic64_dec_and_test(&token->refcnt))
		return;

	INIT_WORK(&token->work, bpf_token_put_deferred);
	schedule_work(&token->work);
}

static int bpf_token_release(struct inode *inode, struct file *filp)
{
	struct bpf_token *token = filp->private_data;

	bpf_token_put(token);
	return 0;
}

static void bpf_token_show_fdinfo(struct seq_file *m, struct file *filp)
{
	struct bpf_token *token = filp->private_data;
	u64 mask;

	BUILD_BUG_ON(__MAX_BPF_CMD >= 64);
	mask = BIT_ULL(__MAX_BPF_CMD) - 1;
	if ((token->allowed_cmds & mask) == mask)
		seq_printf(m, "allowed_cmds:\tany\n");
	else
		seq_printf(m, "allowed_cmds:\t0x%llx\n", token->allowed_cmds);

	BUILD_BUG_ON(__MAX_BPF_MAP_TYPE >= 64);
	mask = BIT_ULL(__MAX_BPF_MAP_TYPE) - 1;
	if ((token->allowed_maps & mask) == mask)
		seq_printf(m, "allowed_maps:\tany\n");
	else
		seq_printf(m, "allowed_maps:\t0x%llx\n", token->allowed_maps);

	BUILD_BUG_ON(__MAX_BPF_PROG_TYPE >= 64);
	mask = BIT_ULL(__MAX_BPF_PROG_TYPE) - 1;
	if ((token->allowed_progs & mask) == mask)
		seq_printf(m, "allowed_progs:\tany\n");
	else
		seq_printf(m, "allowed_progs:\t0x%llx\n", token->allowed_progs);

	BUILD_BUG_ON(__MAX_BPF_ATTACH_TYPE >= 64);
	mask = BIT_ULL(__MAX_BPF_ATTACH_TYPE) - 1;
	if ((token->allowed_attachs & mask) == mask)
		seq_printf(m, "allowed_attachs:\tany\n");
	else
		seq_printf(m, "allowed_attachs:\t0x%llx\n", token->allowed_attachs);
}

#define BPF_TOKEN_INODE_NAME "bpf-token"

static const struct inode_operations bpf_token_iops = { };

const struct file_operations bpf_token_fops = {
	.release	= bpf_token_release,
	.show_fdinfo	= bpf_token_show_fdinfo,
};

int bpf_token_create(union bpf_attr *attr)
{
	struct bpf_mount_opts *mnt_opts;
	struct bpf_token *token = NULL;
	struct user_namespace *userns;
	struct inode *inode;
	struct file *file;
	CLASS(fd, f)(attr->token_create.bpffs_fd);
	struct path path;
	struct super_block *sb;
	umode_t mode;
	int err, fd;

	if (fd_empty(f))
		return -EBADF;

	path = fd_file(f)->f_path;
	sb = path.dentry->d_sb;

	if (path.dentry != sb->s_root)
		return -EINVAL;
	if (sb->s_op != &bpf_super_ops)
		return -EINVAL;
	err = path_permission(&path, MAY_ACCESS);
	if (err)
		return err;

	userns = sb->s_user_ns;
	/*
	 * Enforce that creators of BPF tokens are in the same user
	 * namespace as the BPF FS instance. This makes reasoning about
	 * permissions a lot easier and we can always relax this later.
	 */
	if (current_user_ns() != userns)
		return -EPERM;
	if (!ns_capable(userns, CAP_BPF))
		return -EPERM;

	/* Creating BPF token in init_user_ns doesn't make much sense. */
	if (current_user_ns() == &init_user_ns)
		return -EOPNOTSUPP;

	mnt_opts = sb->s_fs_info;
	if (mnt_opts->delegate_cmds == 0 &&
	    mnt_opts->delegate_maps == 0 &&
	    mnt_opts->delegate_progs == 0 &&
	    mnt_opts->delegate_attachs == 0)
		return -ENOENT; /* no BPF token delegation is set up */

	mode = S_IFREG | ((S_IRUSR | S_IWUSR) & ~current_umask());
	inode = bpf_get_inode(sb, NULL, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &bpf_token_iops;
	inode->i_fop = &bpf_token_fops;
	clear_nlink(inode); /* make sure it is unlinked */

	file = alloc_file_pseudo(inode, path.mnt, BPF_TOKEN_INODE_NAME, O_RDWR, &bpf_token_fops);
	if (IS_ERR(file)) {
		iput(inode);
		return PTR_ERR(file);
	}

	token = kzalloc(sizeof(*token), GFP_USER);
	if (!token) {
		err = -ENOMEM;
		goto out_file;
	}

	atomic64_set(&token->refcnt, 1);

	/* remember bpffs owning userns for future ns_capable() checks */
	token->userns = get_user_ns(userns);

	token->allowed_cmds = mnt_opts->delegate_cmds;
	token->allowed_maps = mnt_opts->delegate_maps;
	token->allowed_progs = mnt_opts->delegate_progs;
	token->allowed_attachs = mnt_opts->delegate_attachs;

	err = security_bpf_token_create(token, attr, &path);
	if (err)
		goto out_token;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		err = fd;
		goto out_token;
	}

	file->private_data = token;
	fd_install(fd, file);

	return fd;

out_token:
	bpf_token_free(token);
out_file:
	fput(file);
	return err;
}

int bpf_token_get_info_by_fd(struct bpf_token *token,
			     const union bpf_attr *attr,
			     union bpf_attr __user *uattr)
{
	struct bpf_token_info __user *uinfo = u64_to_user_ptr(attr->info.info);
	struct bpf_token_info info;
	u32 info_len = attr->info.info_len;

	info_len = min_t(u32, info_len, sizeof(info));
	memset(&info, 0, sizeof(info));

	info.allowed_cmds = token->allowed_cmds;
	info.allowed_maps = token->allowed_maps;
	info.allowed_progs = token->allowed_progs;
	info.allowed_attachs = token->allowed_attachs;

	if (copy_to_user(uinfo, &info, info_len) ||
	    put_user(info_len, &uattr->info.info_len))
		return -EFAULT;

	return 0;
}

struct bpf_token *bpf_token_get_from_fd(u32 ufd)
{
	CLASS(fd, f)(ufd);
	struct bpf_token *token;

	if (fd_empty(f))
		return ERR_PTR(-EBADF);
	if (fd_file(f)->f_op != &bpf_token_fops)
		return ERR_PTR(-EINVAL);

	token = fd_file(f)->private_data;
	bpf_token_inc(token);

	return token;
}

bool bpf_token_allow_cmd(const struct bpf_token *token, enum bpf_cmd cmd)
{
	if (!token)
		return false;
	if (!(token->allowed_cmds & BIT_ULL(cmd)))
		return false;
	return security_bpf_token_cmd(token, cmd) == 0;
}

bool bpf_token_allow_map_type(const struct bpf_token *token, enum bpf_map_type type)
{
	if (!token || type >= __MAX_BPF_MAP_TYPE)
		return false;

	return token->allowed_maps & BIT_ULL(type);
}

bool bpf_token_allow_prog_type(const struct bpf_token *token,
			       enum bpf_prog_type prog_type,
			       enum bpf_attach_type attach_type)
{
	if (!token || prog_type >= __MAX_BPF_PROG_TYPE || attach_type >= __MAX_BPF_ATTACH_TYPE)
		return false;

	return (token->allowed_progs & BIT_ULL(prog_type)) &&
	       (token->allowed_attachs & BIT_ULL(attach_type));
}
