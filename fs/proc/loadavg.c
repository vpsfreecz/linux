// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/pid_namespace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/stat.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/time.h>
#include <linux/cgroup.h>
#include <linux/vpsadminos.h>
#include "internal.h"

static int loadavg_proc_show(struct seq_file *m, void *v)
{
	unsigned long avnrun[3];
	int nr_r; uint nr_t;

	if (get_avenrun_fake(current, avnrun, FIXED_1/200, 0)) {
		nr_r = cgroup_ns_nr_running(current);
		nr_t = cgroup_ns_nr_threads(current);
	} else {
		get_avenrun(avnrun, FIXED_1/200, 0);
		nr_r = nr_running();
		nr_t = nr_threads;
	}

	seq_printf(m, "%lu.%02lu %lu.%02lu %lu.%02lu %u/%d %d\n",
		LOAD_INT(avnrun[0]), LOAD_FRAC(avnrun[0]),
		LOAD_INT(avnrun[1]), LOAD_FRAC(avnrun[1]),
		LOAD_INT(avnrun[2]), LOAD_FRAC(avnrun[2]),
		nr_r, nr_t,
		idr_get_cursor(&task_active_pid_ns(current)->idr) - 1);
	return 0;
}

static int __init proc_loadavg_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("loadavg", 0, NULL, loadavg_proc_show);
	pde_make_permanent(pde);

	pde = proc_create_single("loadavg", 0, proc_vpsadminos, virt_loadavg_proc_show);
	pde_make_permanent(pde);
	return 0;
}
fs_initcall(proc_loadavg_init);
