// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Hammerspace Inc
 */

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/nfs_fs.h>
#include <linux/rcupdate.h>
#include <linux/lockd/bind.h>
#include <linux/capability.h>
#include <linux/user_namespace.h>

#include "internal.h"
#include "nfs4_fs.h"
#include "netns.h"
#include "sysfs.h"

static struct kset *nfs_kset;

static void nfs_kset_release(struct kobject *kobj)
{
	struct kset *kset = container_of(kobj, struct kset, kobj);
	kfree(kset);
}

static const struct kobj_ns_type_operations *nfs_netns_object_child_ns_type(
		const struct kobject *kobj)
{
	return &net_ns_type_operations;
}

static struct kobj_type nfs_kset_type = {
	.release = nfs_kset_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.child_ns_type = nfs_netns_object_child_ns_type,
};

int nfs_sysfs_init(void)
{
	int ret;

	nfs_kset = kzalloc(sizeof(*nfs_kset), GFP_KERNEL);
	if (!nfs_kset)
		return -ENOMEM;

	ret = kobject_set_name(&nfs_kset->kobj, "nfs");
	if (ret) {
		kfree(nfs_kset);
		return ret;
	}

	nfs_kset->kobj.parent = fs_kobj;
	nfs_kset->kobj.ktype = &nfs_kset_type;
	nfs_kset->kobj.kset = NULL;

	ret = kset_register(nfs_kset);
	if (ret) {
		kfree(nfs_kset);
		return ret;
	}

	return 0;
}

void nfs_sysfs_exit(void)
{
	kset_unregister(nfs_kset);
}

static ssize_t nfs_netns_identifier_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client,
			kobject);
	ssize_t ret;

	rcu_read_lock();
	ret = sysfs_emit(buf, "%s\n", rcu_dereference(c->identifier));
	rcu_read_unlock();
	return ret;
}

/* Strip trailing '\n' */
static size_t nfs_string_strip(const char *c, size_t len)
{
	while (len > 0 && c[len-1] == '\n')
		--len;
	return len;
}

static ssize_t nfs_netns_identifier_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client,
			kobject);
	const char *old;
	char *p;
	size_t len;

	len = nfs_string_strip(buf, min_t(size_t, count, CONTAINER_ID_MAXLEN));
	if (!len)
		return 0;
	p = kmemdup_nul(buf, len, GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	old = rcu_dereference_protected(xchg(&c->identifier, (char __rcu *)p), 1);
	if (old) {
		synchronize_rcu();
		kfree(old);
	}
	return count;
}

static void nfs_netns_client_release(struct kobject *kobj)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client,
			kobject);

	kfree(rcu_dereference_raw(c->identifier));
	/* Keep the shared allocation until this child has been released. */
	kobject_put(&c->nfs_net_kobj);
}

static const void *nfs_netns_client_namespace(const struct kobject *kobj)
{
	return container_of(kobj, struct nfs_netns_client, kobject)->net;
}

static struct kobj_attribute nfs_netns_client_id = __ATTR(identifier,
		0644, nfs_netns_identifier_show, nfs_netns_identifier_store);

static ssize_t nfs_netns_shutdown_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client, kobject);
	struct nfs_net *nn = net_generic(c->net, nfs_net_id);

	return sysfs_emit(buf, "%d\n", READ_ONCE(nn->shutdown));
}

static ssize_t nfs_netns_shutdown_store_common(struct kobject *kobj,
		const char *buf, size_t count, bool subtree)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client, kobject);
	int ret, val;

	/* A host teardown operation, never a tenant or initial-netns control. */
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN) ||
	    c->net->user_ns == &init_user_ns)
		return -EPERM;
	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;
	if (val != 1)
		return -EINVAL;

	if (subtree)
		nfs_shutdown_userns(c->net->user_ns);
	else
		nfs_shutdown_net(c->net);
	return count;
}

static ssize_t nfs_netns_shutdown_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	return nfs_netns_shutdown_store_common(kobj, buf, count, false);
}

static ssize_t nfs_netns_shutdown_tree_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client, kobject);

	return sysfs_emit(buf, "%d\n", rpc_userns_shutdown(c->net->user_ns));
}

static ssize_t nfs_netns_shutdown_tree_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	return nfs_netns_shutdown_store_common(kobj, buf, count, true);
}

static struct kobj_attribute nfs_netns_shutdown_tree = __ATTR(shutdown_tree,
		0600, nfs_netns_shutdown_tree_show, nfs_netns_shutdown_tree_store);

static struct kobj_attribute nfs_netns_shutdown = __ATTR(shutdown, 0600,
		nfs_netns_shutdown_show, nfs_netns_shutdown_store);

static struct attribute *nfs_netns_client_attrs[] = {
	&nfs_netns_client_id.attr,
	&nfs_netns_shutdown.attr,
	&nfs_netns_shutdown_tree.attr,
	NULL,
};
ATTRIBUTE_GROUPS(nfs_netns_client);

static struct kobj_type nfs_netns_client_type = {
	.release = nfs_netns_client_release,
	.default_groups = nfs_netns_client_groups,
	.sysfs_ops = &kobj_sysfs_ops,
	.namespace = nfs_netns_client_namespace,
};

static void nfs_netns_object_release(struct kobject *kobj)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client,
			nfs_net_kobj);
	kfree(c);
}

static const void *nfs_netns_namespace(const struct kobject *kobj)
{
	return container_of(kobj, struct nfs_netns_client, nfs_net_kobj)->net;
}

static struct kobj_type nfs_netns_object_type = {
	.release = nfs_netns_object_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.namespace =  nfs_netns_namespace,
};

static struct nfs_netns_client *nfs_netns_client_alloc(struct kobject *parent,
		struct net *net)
{
	struct nfs_netns_client *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (p) {
		p->net = net;
		p->kobject.kset = nfs_kset;
		p->nfs_net_kobj.kset = nfs_kset;

		if (kobject_init_and_add(&p->nfs_net_kobj, &nfs_netns_object_type,
					parent, "net") != 0) {
			kobject_put(&p->nfs_net_kobj);
			return NULL;
		}

		/* kobject_del() drops the hierarchy reference before release. */
		kobject_get(&p->nfs_net_kobj);
		if (kobject_init_and_add(&p->kobject, &nfs_netns_client_type,
					&p->nfs_net_kobj, "nfs_client") == 0)
			return p;

		kobject_put(&p->kobject);
		kobject_put(&p->nfs_net_kobj);
	}
	return NULL;
}

void nfs_netns_sysfs_setup(struct nfs_net *netns, struct net *net)
{
	struct nfs_netns_client *clp;

	clp = nfs_netns_client_alloc(&nfs_kset->kobj, net);
	if (clp) {
		netns->nfs_client = clp;
		kobject_uevent(&clp->kobject, KOBJ_ADD);
	}
}

void nfs_netns_sysfs_destroy(struct nfs_net *netns)
{
	struct nfs_netns_client *clp = netns->nfs_client;

	if (clp) {
		kobject_uevent(&clp->kobject, KOBJ_REMOVE);
		kobject_del(&clp->kobject);
		kobject_put(&clp->kobject);
		kobject_del(&clp->nfs_net_kobj);
		kobject_put(&clp->nfs_net_kobj);
		netns->nfs_client = NULL;
	}
}

static void shutdown_client(struct rpc_clnt *clnt)
{
	rpc_cancel_client(clnt);
}

/*
 * Shut down the nfs_client only once all the superblocks
 * have been shut down.
 */
static void shutdown_nfs_client(struct nfs_client *clp)
{
	struct nfs_net *nn = net_generic(clp->cl_net, nfs_net_id);
	struct nfs_server *server;

	lockdep_assert_held(&nn->nfs_server_lock);
	spin_lock(&nn->nfs_client_lock);
	list_for_each_entry(server, &clp->cl_superblocks, client_link) {
		if (!(server->flags & NFS_MOUNT_SHUTDOWN)) {
			spin_unlock(&nn->nfs_client_lock);
			return;
		}
	}
	nfs_mark_client_ready_locked(clp, -EIO);
	spin_unlock(&nn->nfs_client_lock);
	shutdown_client(clp->cl_rpcclient);
}

static void shutdown_nlm_client(struct nfs_server *server, struct nfs_net *nn)
{
	struct nfs_server *other;

	if (!server->nlm_host)
		return;
	lockdep_assert_held(&nn->nfs_server_lock);
	list_for_each_entry(other, &nn->nfs_volume_list, master_link) {
		if (other->nlm_host == server->nlm_host &&
		    !(other->flags & NFS_MOUNT_SHUTDOWN))
			return;
	}
	nlmclnt_shutdown_rpc_clnt(server->nlm_host);
}

static ssize_t
shutdown_show(struct kobject *kobj, struct kobj_attribute *attr,
				char *buf)
{
	struct nfs_server *server = container_of(kobj, struct nfs_server, kobj);
	bool shutdown = READ_ONCE(server->flags) & NFS_MOUNT_SHUTDOWN;
	return sysfs_emit(buf, "%d\n", shutdown);
}

static ssize_t
shutdown_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct nfs_server *server;
	struct nfs_net *nn;
	int ret, val;

	server = container_of(kobj, struct nfs_server, kobj);

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val != 1)
		return -EINVAL;

	/* nfs_client can be replaced during migration or mount error unwind. */
	nn = net_generic(server->sysfs_net, nfs_net_id);
	mutex_lock(&nn->nfs_server_lock);
	/* The temporary server-N object can be visible before mount setup. */
	if (list_empty(&server->master_link) || IS_ERR_OR_NULL(server->client)) {
		mutex_unlock(&nn->nfs_server_lock);
		return -EAGAIN;
	}

	/* already shut down? */
	if (server->flags & NFS_MOUNT_SHUTDOWN)
		goto out;

	WRITE_ONCE(server->flags, server->flags | NFS_MOUNT_SHUTDOWN);
	shutdown_client(server->client);

	if (!IS_ERR(server->client_acl))
		shutdown_client(server->client_acl);

out:
	shutdown_nlm_client(server, nn);
	shutdown_nfs_client(server->nfs_client);
	mutex_unlock(&nn->nfs_server_lock);
	return count;
}

static struct kobj_attribute nfs_sysfs_attr_shutdown = __ATTR_RW(shutdown);

#define RPC_CLIENT_NAME_SIZE 64

void nfs_sysfs_link_rpc_client(struct nfs_server *server,
			struct rpc_clnt *clnt, const char *uniq)
{
	char name[RPC_CLIENT_NAME_SIZE];
	int ret;

	strscpy(name, clnt->cl_program->name, sizeof(name));
	strncat(name, uniq ? uniq : "", sizeof(name) - strlen(name) - 1);
	strncat(name, "_client", sizeof(name) - strlen(name) - 1);

	ret = sysfs_create_link_nowarn(&server->kobj,
						&clnt->cl_sysfs->kobject, name);
	if (ret < 0)
		pr_warn("NFS: can't create link to %s in sysfs (%d)\n",
			name, ret);
}
EXPORT_SYMBOL_GPL(nfs_sysfs_link_rpc_client);

static void nfs_sysfs_sb_release(struct kobject *kobj)
{
	nfs_release_server(container_of(kobj, struct nfs_server, kobj));
}

static const void *nfs_netns_server_namespace(const struct kobject *kobj)
{
	return container_of(kobj, struct nfs_server, kobj)->sysfs_net;
}

static struct kobj_type nfs_sb_ktype = {
	.release = nfs_sysfs_sb_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.namespace = nfs_netns_server_namespace,
	.child_ns_type = nfs_netns_object_child_ns_type,
};

void nfs_sysfs_add_server(struct nfs_server *server)
{
	int ret;

	/* Migration replaces the client, not the existing sysfs object. */
	if (server->kobj.state_initialized)
		return;

	server->sysfs_net = get_net(server->nfs_client->cl_net);
	ret = kobject_init_and_add(&server->kobj, &nfs_sb_ktype,
				&nfs_kset->kobj, "server-%d", server->s_sysfs_id);
	if (ret < 0) {
		pr_warn("NFS: nfs sysfs add server-%d failed (%d)\n",
					server->s_sysfs_id, ret);
		return;
	}
	ret = sysfs_create_file_ns(&server->kobj, &nfs_sysfs_attr_shutdown.attr,
				nfs_netns_server_namespace(&server->kobj));
	if (ret < 0)
		pr_warn("NFS: sysfs_create_file_ns for server-%d failed (%d)\n",
			server->s_sysfs_id, ret);
}
EXPORT_SYMBOL_GPL(nfs_sysfs_add_server);

void nfs_sysfs_move_server_to_sb(struct super_block *s)
{
	struct nfs_server *server = s->s_fs_info;
	int ret;

	ret = kobject_rename(&server->kobj, s->s_id);
	if (ret < 0)
		pr_warn("NFS: rename sysfs %s failed (%d)\n",
					server->kobj.name, ret);
}

void nfs_sysfs_move_sb_to_server(struct nfs_server *server)
{
	const char *s;
	int ret = -ENOMEM;

	s = kasprintf(GFP_KERNEL, "server-%d", server->s_sysfs_id);
	if (s) {
		ret = kobject_rename(&server->kobj, s);
		kfree(s);
	}
	if (ret < 0)
		pr_warn("NFS: rename sysfs %s failed (%d)\n",
					server->kobj.name, ret);
}

/* unlink, not dec-ref */
void nfs_sysfs_remove_server(struct nfs_server *server)
{
	kobject_del(&server->kobj);
}
