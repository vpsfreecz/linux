/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * internal.h - printk internal definitions
 */
#include <linux/percpu.h>
#include <linux/types.h>
#include <linux/syslog_namespace.h>
#include <linux/printk_ringbuffer.h>

#if defined(CONFIG_PRINTK) && defined(CONFIG_SYSCTL)
void __init printk_sysctl_init(void);
int devkmsg_sysctl_set_loglvl(struct ctl_table *table, int write,
			      void *buffer, size_t *lenp, loff_t *ppos);
#else
#define printk_sysctl_init() do { } while (0)
#endif

#ifdef CONFIG_PRINTK

#ifdef CONFIG_PRINTK_CALLER
#define PRINTK_PREFIX_MAX	48
#else
#define PRINTK_PREFIX_MAX	32
#endif

/*
 * the maximum size of a formatted record (i.e. with prefix added
 * per line and dropped messages or in extended message format)
 */
#define PRINTK_MESSAGE_MAX	2048

/* the maximum size allowed to be reserved for a record */
#define PRINTKRB_RECORD_MAX	1024

/* the maximum size of a formatted record (i.e. with prefix added per line) */
#define CONSOLE_LOG_MAX                1024

/* the maximum size for a dropped text message */
#define DROPPED_TEXT_MAX       64

/* the maximum size allowed to be reserved for a record */
#define LOG_LINE_MAX           (CONSOLE_LOG_MAX - PRINTK_PREFIX_MAX)

struct printk_ringbuffer;
struct dev_printk_info;

extern struct printk_ringbuffer *prb;
extern bool printk_kthreads_running;

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


struct syslog_namespace;
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
