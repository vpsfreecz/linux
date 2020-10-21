#include <linux/memcontrol.h>
#include <linux/user_namespace.h>

static inline struct user_namespace *current_1stlvl_user_ns(void)
{
	struct user_namespace *ns = current_user_ns();

	if (ns == &init_user_ns)
		return ns;

	while (ns->parent != &init_user_ns)
		ns = ns->parent;

	return ns;
}

struct mem_cgroup *get_current_most_limited_memcg(void);
