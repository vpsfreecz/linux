/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * internal.h - printk internal definitions
 */
#include <linux/syslog_namespace.h>
#include <linux/percpu.h>

#if defined(CONFIG_PRINTK) && defined(CONFIG_SYSCTL)
void __init printk_sysctl_init(void);
int devkmsg_sysctl_set_loglvl(struct ctl_table *table, int write,
			      void *buffer, size_t *lenp, loff_t *ppos);
#else
#define printk_sysctl_init() do { } while (0)
#endif

#ifdef CONFIG_PRINTK

struct syslog_namespace;

__printf(5, 0)
int vprintk_store_ns(struct syslog_namespace *ns, int facility, int level,
		  const struct dev_printk_info *dev_info,
		  const char *fmt, va_list args);

__printf(2, 0) int vprintk_ns(struct syslog_namespace *ns,
		  const char *fmt, va_list args);
__printf(1, 0) int vprintk_default(const char *fmt, va_list args);
__printf(1, 0) int vprintk_deferred(const char *fmt, va_list args);

bool printk_percpu_data_ready(void);

#define printk_safe_enter_irqsave(flags)	\
	do {					\
		local_irq_save(flags);		\
		__printk_safe_enter();		\
	} while (0)

#define printk_safe_exit_irqrestore(flags)	\
	do {					\
		__printk_safe_exit();		\
		local_irq_restore(flags);	\
	} while (0)

void defer_console_output(struct syslog_namespace *ns);

u16 printk_parse_prefix(const char *text, int *level,
			enum printk_info_flags *flags);
#else

/*
 * In !PRINTK builds we still export console_sem
 * semaphore and some of console functions (console_unlock()/etc.), so
 * printk-safe must preserve the existing local IRQ guarantees.
 */
#define printk_safe_enter_irqsave(flags) local_irq_save(flags)
#define printk_safe_exit_irqrestore(flags) local_irq_restore(flags)

static inline bool printk_percpu_data_ready(void) { return false; }
#endif /* CONFIG_PRINTK */
