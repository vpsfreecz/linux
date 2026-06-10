// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/wait.h>
#include <linux/lockdep.h>
#include <linux/percpu-rwsem.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/debug.h>
#include <linux/errno.h>
#include <trace/events/lock.h>

#define per_cpu_sum(var)						\
({									\
	TYPEOF_UNQUAL(var) __sum = 0;					\
	int cpu;							\
	compiletime_assert_atomic_type(__sum);				\
	for_each_possible_cpu(cpu)					\
		__sum += per_cpu(var, cpu);				\
	__sum;								\
})

#ifdef CONFIG_SCHED_PROXY_EXEC
#define PERCPU_RWSEM_PROXY_READERS ARRAY_SIZE(((struct percpu_rw_semaphore *)0)->proxy_readers)
#define PERCPU_RWSEM_PROXY_READER_LOCKED 1UL
#define PERCPU_RWSEM_PROXY_READER_MASK (~PERCPU_RWSEM_PROXY_READER_LOCKED)
#define PERCPU_RWSEM_PROXY_READER_TRYLOCK_ATTEMPTS 4

static inline struct task_struct *
percpu_rwsem_proxy_reader_task(unsigned long value)
{
	return (struct task_struct *)(value & PERCPU_RWSEM_PROXY_READER_MASK);
}

static bool
percpu_rwsem_proxy_reader_trylock(struct percpu_rwsem_proxy_reader_slot *slot,
				  unsigned long *value)
{
	unsigned long old;
	int attempts;

	for (attempts = 0; attempts < PERCPU_RWSEM_PROXY_READER_TRYLOCK_ATTEMPTS;
	     attempts++) {
		old = READ_ONCE(slot->task);
		if (old & PERCPU_RWSEM_PROXY_READER_LOCKED)
			return false;
		if (cmpxchg(&slot->task, old,
			    old | PERCPU_RWSEM_PROXY_READER_LOCKED) == old) {
			*value = old;
			return true;
		}
		cpu_relax();
	}

	return false;
}

/*
 * Scheduler owner sampling must fail fast, but read-side maintenance must not
 * lose acquire/release accounting just because the sampled slot is busy.
 */
static void
percpu_rwsem_proxy_reader_lock(struct percpu_rwsem_proxy_reader_slot *slot,
			       unsigned long *value)
{
	while (!percpu_rwsem_proxy_reader_trylock(slot, value))
		cpu_relax();
}

static bool
percpu_rwsem_proxy_reader_lock_maybe(
	struct percpu_rwsem_proxy_reader_slot *slot,
	unsigned long *value, bool wait)
{
	if (!wait)
		return percpu_rwsem_proxy_reader_trylock(slot, value);

	percpu_rwsem_proxy_reader_lock(slot, value);
	return true;
}

static void
percpu_rwsem_proxy_reader_unlock(struct percpu_rwsem_proxy_reader_slot *slot,
				 struct task_struct *reader)
{
	smp_store_release(&slot->task, (unsigned long)reader);
}

static struct task_struct *
percpu_rwsem_proxy_reader_owner(struct percpu_rw_semaphore *sem)
{
	struct percpu_rwsem_proxy_reader_slot *slot;
	struct task_struct *reader;
	struct task_struct *best_reader = NULL;
	unsigned long value;
	int best_score = -1;
	int i;

	for (i = 0; i < PERCPU_RWSEM_PROXY_READERS; i++) {
		int reader_score;

		slot = &sem->proxy_readers[i];
		value = READ_ONCE(slot->task);
		if (!percpu_rwsem_proxy_reader_task(value))
			continue;
		if (!percpu_rwsem_proxy_reader_trylock(slot, &value))
			continue;

		reader = percpu_rwsem_proxy_reader_task(value);
		reader_score = sched_proxy_exec_lock_owner_score(reader);
		if (reader && reader_score > best_score) {
			get_task_struct(reader);
			if (best_reader)
				put_task_struct(best_reader);
			best_reader = reader;
			best_score = reader_score;
		}
		percpu_rwsem_proxy_reader_unlock(slot, reader);
	}

	return best_reader;
}

static bool __percpu_rwsem_proxy_read_track(struct percpu_rw_semaphore *sem,
					    struct task_struct *task,
					    bool counted, bool wait)
{
	unsigned int start;
	int i;

	if (!sched_proxy_exec())
		return false;

	for (i = 0; i < PERCPU_RWSEM_PROXY_READERS; i++) {
		struct percpu_rwsem_proxy_reader_slot *slot =
			&sem->proxy_readers[i];
		struct task_struct *reader;
		unsigned long value;

		value = READ_ONCE(slot->task);
		if (percpu_rwsem_proxy_reader_task(value) != task)
			continue;
		if (!percpu_rwsem_proxy_reader_lock_maybe(slot, &value, wait))
			return false;

		reader = percpu_rwsem_proxy_reader_task(value);
		if (reader == task) {
			if (counted)
				WRITE_ONCE(slot->count,
					   READ_ONCE(slot->count) + 1);
			percpu_rwsem_proxy_reader_unlock(slot, reader);
			return true;
		}
		percpu_rwsem_proxy_reader_unlock(slot, reader);
	}

	get_task_struct(task);
	for (i = 0; i < PERCPU_RWSEM_PROXY_READERS; i++) {
		struct percpu_rwsem_proxy_reader_slot *slot =
			&sem->proxy_readers[i];
		struct task_struct *reader;
		unsigned long value;

		value = READ_ONCE(slot->task);
		if (percpu_rwsem_proxy_reader_task(value))
			continue;
		if (!percpu_rwsem_proxy_reader_lock_maybe(slot, &value, wait))
			continue;

		reader = percpu_rwsem_proxy_reader_task(value);
		if (!reader) {
			WRITE_ONCE(slot->count, counted ? 1 : 0);
			percpu_rwsem_proxy_reader_unlock(slot, task);
			return true;
		}
		if (reader == task) {
			if (counted)
				WRITE_ONCE(slot->count,
					   READ_ONCE(slot->count) + 1);
			percpu_rwsem_proxy_reader_unlock(slot, reader);
			put_task_struct(task);
			return true;
		}
		percpu_rwsem_proxy_reader_unlock(slot, reader);
	}

	start = atomic_inc_return(&sem->proxy_readers_next);
	{
		unsigned int victim = start % PERCPU_RWSEM_PROXY_READERS;
		struct percpu_rwsem_proxy_reader_slot *slot =
			&sem->proxy_readers[victim];
		struct task_struct *reader;
		int task_score = sched_proxy_exec_lock_owner_score(task);
		int victim_score = 0;
		bool have_victim = false;
		unsigned long value;

		for (i = 0; i < PERCPU_RWSEM_PROXY_READERS; i++) {
			unsigned int idx =
				(start + i) % PERCPU_RWSEM_PROXY_READERS;
			struct percpu_rwsem_proxy_reader_slot *sample_slot =
				&sem->proxy_readers[idx];
			struct task_struct *sample;
			int sample_score;

			if (!percpu_rwsem_proxy_reader_lock_maybe(sample_slot,
								  &value, wait))
				continue;
			sample = percpu_rwsem_proxy_reader_task(value);
			if (sample == task) {
				if (counted)
					WRITE_ONCE(sample_slot->count,
						   READ_ONCE(sample_slot->count) + 1);
				percpu_rwsem_proxy_reader_unlock(sample_slot, sample);
				put_task_struct(task);
				return true;
			}
			sample_score = sched_proxy_exec_lock_owner_score(sample);
			if (!have_victim || sample_score < victim_score) {
				victim = idx;
				victim_score = sample_score;
				have_victim = true;
			}
			percpu_rwsem_proxy_reader_unlock(sample_slot, sample);
			if (!sample || task_score > sample_score)
				break;
		}

		slot = &sem->proxy_readers[victim];
		if (!percpu_rwsem_proxy_reader_lock_maybe(slot, &value, wait)) {
			put_task_struct(task);
			return false;
		}

		reader = percpu_rwsem_proxy_reader_task(value);
		if (reader == task) {
			if (counted)
				WRITE_ONCE(slot->count,
					   READ_ONCE(slot->count) + 1);
			percpu_rwsem_proxy_reader_unlock(slot, reader);
			put_task_struct(task);
			return true;
		}

		if (reader &&
		    task_score < sched_proxy_exec_lock_owner_score(reader)) {
			percpu_rwsem_proxy_reader_unlock(slot, reader);
			put_task_struct(task);
			return false;
		}

		WRITE_ONCE(slot->count, counted ? 1 : 0);
		percpu_rwsem_proxy_reader_unlock(slot, task);
		if (reader)
			put_task_struct(reader);
		return true;
	}

	put_task_struct(task);
	return false;
}

bool percpu_rwsem_proxy_read_try_acquire(struct percpu_rw_semaphore *sem)
{
	return __percpu_rwsem_proxy_read_track(sem, current, true, false);
}
EXPORT_SYMBOL_GPL(percpu_rwsem_proxy_read_try_acquire);

void percpu_rwsem_proxy_read_acquire(struct percpu_rw_semaphore *sem)
{
	__percpu_rwsem_proxy_read_track(sem, current, true, true);
}
EXPORT_SYMBOL_GPL(percpu_rwsem_proxy_read_acquire);

void percpu_rwsem_proxy_read_wake_acquire(struct percpu_rw_semaphore *sem,
					  struct task_struct *reader)
{
	__percpu_rwsem_proxy_read_track(sem, reader, false, false);
}
EXPORT_SYMBOL_GPL(percpu_rwsem_proxy_read_wake_acquire);

static bool __percpu_rwsem_proxy_read_release(struct percpu_rw_semaphore *sem,
					      bool wait)
{
	int i;

	if (!sched_proxy_exec())
		return true;

	for (i = 0; i < PERCPU_RWSEM_PROXY_READERS; i++) {
		struct percpu_rwsem_proxy_reader_slot *slot =
			&sem->proxy_readers[i];
		struct task_struct *reader;
		unsigned int count;
		unsigned long value;

		value = READ_ONCE(slot->task);
		if (percpu_rwsem_proxy_reader_task(value) != current)
			continue;
		if (!percpu_rwsem_proxy_reader_lock_maybe(slot, &value, wait))
			return false;

		reader = percpu_rwsem_proxy_reader_task(value);
		if (reader != current) {
			percpu_rwsem_proxy_reader_unlock(slot, reader);
			continue;
		}

		count = READ_ONCE(slot->count);
		if (count > 1) {
			WRITE_ONCE(slot->count, count - 1);
			percpu_rwsem_proxy_reader_unlock(slot, reader);
		} else {
			WRITE_ONCE(slot->count, 0);
			percpu_rwsem_proxy_reader_unlock(slot, NULL);
			put_task_struct(current);
		}
		return true;
	}

	return true;
}

bool percpu_rwsem_proxy_read_try_release(struct percpu_rw_semaphore *sem)
{
	return __percpu_rwsem_proxy_read_release(sem, false);
}
EXPORT_SYMBOL_GPL(percpu_rwsem_proxy_read_try_release);

void percpu_rwsem_proxy_read_release(struct percpu_rw_semaphore *sem)
{
	__percpu_rwsem_proxy_read_release(sem, true);
}
EXPORT_SYMBOL_GPL(percpu_rwsem_proxy_read_release);

static void percpu_rwsem_proxy_readers_clear(struct percpu_rw_semaphore *sem)
{
	int i;

	for (i = 0; i < PERCPU_RWSEM_PROXY_READERS; i++) {
		struct percpu_rwsem_proxy_reader_slot *slot =
			&sem->proxy_readers[i];
		struct task_struct *reader;
		unsigned long value;

		percpu_rwsem_proxy_reader_lock(slot, &value);

		reader = percpu_rwsem_proxy_reader_task(value);
		WRITE_ONCE(slot->count, 0);
		percpu_rwsem_proxy_reader_unlock(slot, NULL);
		if (reader)
			put_task_struct(reader);
	}
}

static inline void
__percpu_rwsem_set_owner_task(struct percpu_rw_semaphore *sem,
			      struct task_struct *owner)
{
	lockdep_assert_held(&sem->waiters.lock);
	WRITE_ONCE(sem->proxy_owner, owner);
	if (!owner)
		WRITE_ONCE(sem->proxy_writer_waiting_readers, false);
}

static inline void percpu_rwsem_set_owner(struct percpu_rw_semaphore *sem)
{
	unsigned long flags;

	if (!sched_proxy_exec())
		return;

	spin_lock_irqsave(&sem->waiters.lock, flags);
	__percpu_rwsem_set_owner_task(sem, current);
	spin_unlock_irqrestore(&sem->waiters.lock, flags);
}

static inline void percpu_rwsem_clear_owner(struct percpu_rw_semaphore *sem)
{
	unsigned long flags;

	if (!sched_proxy_exec())
		return;

	spin_lock_irqsave(&sem->waiters.lock, flags);
	__percpu_rwsem_set_owner_task(sem, NULL);
	spin_unlock_irqrestore(&sem->waiters.lock, flags);
}

static inline void
__percpu_rwsem_set_writer_waiting_readers(struct percpu_rw_semaphore *sem,
					  bool waiting)
{
	lockdep_assert_held(&sem->waiters.lock);
	WRITE_ONCE(sem->proxy_writer_waiting_readers, waiting);
}

static inline void
percpu_rwsem_set_writer_waiting_readers(struct percpu_rw_semaphore *sem,
					bool waiting)
{
	unsigned long flags;

	if (!sched_proxy_exec())
		return;

	spin_lock_irqsave(&sem->waiters.lock, flags);
	__percpu_rwsem_set_writer_waiting_readers(sem, waiting);
	spin_unlock_irqrestore(&sem->waiters.lock, flags);
}

static inline void percpu_rwsem_set_blocked_on(struct percpu_rw_semaphore *sem)
{
	unsigned long flags;

	if (!sched_proxy_exec())
		return;

	raw_spin_lock_irqsave(&current->blocked_lock, flags);
	__set_task_blocked_on_percpu_rwsem(current, sem);
	raw_spin_unlock_irqrestore(&current->blocked_lock, flags);
}

static inline void percpu_rwsem_clear_blocked_on(struct percpu_rw_semaphore *sem)
{
	if (sched_proxy_exec())
		clear_task_blocked_on_percpu_rwsem(current, sem);
}

static inline void percpu_rwsem_set_waking(struct task_struct *p,
					   struct percpu_rw_semaphore *sem)
{
	if (sched_proxy_exec())
		set_task_blocked_on_percpu_rwsem_waking(p, sem);
}

struct task_struct *
percpu_rwsem_proxy_owner(struct percpu_rw_semaphore *sem,
			 enum percpu_rwsem_proxy_owner_state *state)
{
	struct task_struct *owner;
	bool writer_waiting_readers;

	lockdep_assert_held(&sem->waiters.lock);

	if (!atomic_read(&sem->block)) {
		*state = PERCPU_RWSEM_PROXY_OWNER_OWNERLESS;
		return NULL;
	}

	writer_waiting_readers =
		READ_ONCE(sem->proxy_writer_waiting_readers);
	if (writer_waiting_readers) {
		bool readers_active;

		owner = percpu_rwsem_proxy_reader_owner(sem);
		if (owner) {
			*state = PERCPU_RWSEM_PROXY_OWNER_READER_REPRESENTATIVE;
			return owner;
		}

		readers_active = per_cpu_sum(*sem->read_count) != 0;
		if (readers_active) {
			*state = PERCPU_RWSEM_PROXY_OWNER_READER_UNTRACKED;
			return NULL;
		}

		*state = PERCPU_RWSEM_PROXY_OWNER_OWNERLESS;
		return NULL;
	}

	owner = READ_ONCE(sem->proxy_owner);
	if (!owner) {
		*state = PERCPU_RWSEM_PROXY_OWNER_UNKNOWN;
		return NULL;
	}

	*state = PERCPU_RWSEM_PROXY_OWNER_WRITER;
	get_task_struct(owner);
	return owner;
}
#else
static inline void
__percpu_rwsem_set_owner_task(struct percpu_rw_semaphore *sem,
			      struct task_struct *owner)
{
}
static inline void
percpu_rwsem_set_writer_waiting_readers(struct percpu_rw_semaphore *sem,
					bool waiting)
{
}
static inline void percpu_rwsem_proxy_readers_clear(struct percpu_rw_semaphore *sem) { }
static inline void percpu_rwsem_set_owner(struct percpu_rw_semaphore *sem) { }
static inline void percpu_rwsem_clear_owner(struct percpu_rw_semaphore *sem) { }
static inline void percpu_rwsem_set_blocked_on(struct percpu_rw_semaphore *sem) { }
static inline void percpu_rwsem_clear_blocked_on(struct percpu_rw_semaphore *sem) { }
static inline void percpu_rwsem_set_waking(struct task_struct *p,
					   struct percpu_rw_semaphore *sem)
{
}
#endif

int __percpu_init_rwsem(struct percpu_rw_semaphore *sem,
			const char *name, struct lock_class_key *key)
{
#ifdef CONFIG_SCHED_PROXY_EXEC
	int i;
#endif

	sem->read_count = alloc_percpu(int);
	if (unlikely(!sem->read_count))
		return -ENOMEM;

	rcu_sync_init(&sem->rss);
	rcuwait_init(&sem->writer);
	init_waitqueue_head(&sem->waiters);
	atomic_set(&sem->block, 0);
#ifdef CONFIG_SCHED_PROXY_EXEC
	sem->proxy_owner = NULL;
	sem->proxy_writer_waiting_readers = false;
	for (i = 0; i < PERCPU_RWSEM_PROXY_READERS; i++) {
		sem->proxy_readers[i].task = 0;
		sem->proxy_readers[i].count = 0;
	}
	atomic_set(&sem->proxy_readers_next, 0);
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map(&sem->dep_map, name, key, 0);
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(__percpu_init_rwsem);

void percpu_free_rwsem(struct percpu_rw_semaphore *sem)
{
	/*
	 * XXX: temporary kludge. The error path in alloc_super()
	 * assumes that percpu_free_rwsem() is safe after kzalloc().
	 */
	if (!sem->read_count)
		return;

	percpu_rwsem_proxy_readers_clear(sem);
	rcu_sync_dtor(&sem->rss);
	free_percpu(sem->read_count);
	sem->read_count = NULL; /* catch use after free bugs */
}
EXPORT_SYMBOL_GPL(percpu_free_rwsem);

static bool __percpu_down_read_trylock(struct percpu_rw_semaphore *sem)
{
	this_cpu_inc(*sem->read_count);

	/*
	 * Due to having preemption disabled the decrement happens on
	 * the same CPU as the increment, avoiding the
	 * increment-on-one-CPU-and-decrement-on-another problem.
	 *
	 * If the reader misses the writer's assignment of sem->block, then the
	 * writer is guaranteed to see the reader's increment.
	 *
	 * Conversely, any readers that increment their sem->read_count after
	 * the writer looks are guaranteed to see the sem->block value, which
	 * in turn means that they are guaranteed to immediately decrement
	 * their sem->read_count, so that it doesn't matter that the writer
	 * missed them.
	 */

	smp_mb(); /* A matches D */

	/*
	 * If !sem->block the critical section starts here, matched by the
	 * release in percpu_up_write().
	 */
	if (likely(!atomic_read_acquire(&sem->block)))
		return true;

	this_cpu_dec(*sem->read_count);

	/* Prod writer to re-evaluate readers_active_check() */
	rcuwait_wake_up(&sem->writer);

	return false;
}

static inline bool __percpu_down_write_trylock(struct percpu_rw_semaphore *sem)
{
	if (atomic_read(&sem->block))
		return false;

	return atomic_xchg(&sem->block, 1) == 0;
}

static bool __percpu_rwsem_trylock(struct percpu_rw_semaphore *sem, bool reader)
{
	if (reader) {
		bool ret;

		preempt_disable();
		ret = __percpu_down_read_trylock(sem);
		preempt_enable();

		return ret;
	}
	return __percpu_down_write_trylock(sem);
}

/*
 * The return value of wait_queue_entry::func means:
 *
 *  <0 - error, wakeup is terminated and the error is returned
 *   0 - no wakeup, a next waiter is tried
 *  >0 - woken, if EXCLUSIVE, counted towards @nr_exclusive.
 *
 * We use EXCLUSIVE for both readers and writers to preserve FIFO order,
 * and play games with the return value to allow waking multiple readers.
 *
 * Specifically, we wake readers until we've woken a single writer, or until a
 * trylock fails.
 */
static int percpu_rwsem_wake_function(struct wait_queue_entry *wq_entry,
				      unsigned int mode, int wake_flags,
				      void *key)
{
	bool reader = wq_entry->flags & WQ_FLAG_CUSTOM;
	struct percpu_rw_semaphore *sem = key;
	struct task_struct *p;

	/* concurrent against percpu_down_write(), can get stolen */
	if (!__percpu_rwsem_trylock(sem, reader))
		return 1;

	p = get_task_struct(wq_entry->private);
	if (sched_proxy_exec()) {
		if (reader)
			percpu_rwsem_proxy_read_wake_acquire(sem, p);
		else
			__percpu_rwsem_set_owner_task(sem, p);
	}
	percpu_rwsem_set_waking(p, sem);
	list_del_init(&wq_entry->entry);
	smp_store_release(&wq_entry->private, NULL);

	wake_up_process(p);
	put_task_struct(p);

	return !reader; /* wake (readers until) 1 writer */
}

static void percpu_rwsem_wait(struct percpu_rw_semaphore *sem, bool reader,
			      bool freeze)
{
	DEFINE_WAIT_FUNC(wq_entry, percpu_rwsem_wake_function);
	bool wait;

	spin_lock_irq(&sem->waiters.lock);
	/*
	 * Serialize against the wakeup in percpu_up_write(), if we fail
	 * the trylock, the wakeup must see us on the list.
	 */
	wait = !__percpu_rwsem_trylock(sem, reader);
	if (wait) {
		wq_entry.flags |= WQ_FLAG_EXCLUSIVE | reader * WQ_FLAG_CUSTOM;
		__add_wait_queue_entry_tail(&sem->waiters, &wq_entry);
		percpu_rwsem_set_blocked_on(sem);
	}
	spin_unlock_irq(&sem->waiters.lock);

	while (wait) {
		set_current_state(TASK_UNINTERRUPTIBLE |
				  (freeze ? TASK_FREEZABLE : 0));
		if (!smp_load_acquire(&wq_entry.private))
			break;
		percpu_rwsem_set_blocked_on(sem);
		schedule();
	}
	percpu_rwsem_clear_blocked_on(sem);
	__set_current_state(TASK_RUNNING);
}

bool __sched __percpu_down_read(struct percpu_rw_semaphore *sem, bool try,
				bool freeze)
{
	if (__percpu_down_read_trylock(sem))
		return true;

	if (try)
		return false;

	trace_contention_begin(sem, LCB_F_PERCPU | LCB_F_READ);
	preempt_enable();
	percpu_rwsem_wait(sem, /* .reader = */ true, freeze);
	preempt_disable();
	trace_contention_end(sem, 0);

	return true;
}
EXPORT_SYMBOL_GPL(__percpu_down_read);

bool percpu_is_read_locked(struct percpu_rw_semaphore *sem)
{
	return per_cpu_sum(*sem->read_count) != 0 && !atomic_read(&sem->block);
}
EXPORT_SYMBOL_GPL(percpu_is_read_locked);

/*
 * Return true if the modular sum of the sem->read_count per-CPU variable is
 * zero.  If this sum is zero, then it is stable due to the fact that if any
 * newly arriving readers increment a given counter, they will immediately
 * decrement that same counter.
 *
 * Assumes sem->block is set.
 */
static bool readers_active_check(struct percpu_rw_semaphore *sem)
{
	if (per_cpu_sum(*sem->read_count) != 0)
		return false;

	/*
	 * If we observed the decrement; ensure we see the entire critical
	 * section.
	 */

	smp_mb(); /* C matches B */

	return true;
}

void __sched percpu_down_write(struct percpu_rw_semaphore *sem)
{
	bool waiting_readers = false;
	bool contended = false;

	might_sleep();
	rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);

	/* Notify readers to take the slow path. */
	rcu_sync_enter(&sem->rss);

	/*
	 * Try set sem->block; this provides writer-writer exclusion.
	 * Having sem->block set makes new readers block.
	 */
	if (!__percpu_down_write_trylock(sem)) {
		trace_contention_begin(sem, LCB_F_PERCPU | LCB_F_WRITE);
		percpu_rwsem_wait(sem, /* .reader = */ false, false);
		contended = true;
	}
	percpu_rwsem_set_owner(sem);

	/* smp_mb() implied by __percpu_down_write_trylock() on success -- D matches A */

	/*
	 * If they don't see our store of sem->block, then we are guaranteed to
	 * see their sem->read_count increment, and therefore will wait for
	 * them.
	 */

	/* Wait for all active readers to complete. */
	if (!readers_active_check(sem)) {
		waiting_readers = true;
		percpu_rwsem_set_writer_waiting_readers(sem, true);
		percpu_rwsem_set_blocked_on(sem);
	}
	rcuwait_wait_event(&sem->writer, readers_active_check(sem), TASK_UNINTERRUPTIBLE);
	if (waiting_readers)
		percpu_rwsem_set_writer_waiting_readers(sem, false);
	percpu_rwsem_clear_blocked_on(sem);
	if (contended)
		trace_contention_end(sem, 0);
}
EXPORT_SYMBOL_GPL(percpu_down_write);

void percpu_up_write(struct percpu_rw_semaphore *sem)
{
	rwsem_release(&sem->dep_map, _RET_IP_);
	percpu_rwsem_clear_owner(sem);

	/*
	 * Signal the writer is done, no fast path yet.
	 *
	 * One reason that we cannot just immediately flip to readers_fast is
	 * that new readers might fail to see the results of this writer's
	 * critical section.
	 *
	 * Therefore we force it through the slow path which guarantees an
	 * acquire and thereby guarantees the critical section's consistency.
	 */
	atomic_set_release(&sem->block, 0);

	/*
	 * Prod any pending reader/writer to make progress.
	 */
	__wake_up(&sem->waiters, TASK_NORMAL, 1, sem);

	/*
	 * Once this completes (at least one RCU-sched grace period hence) the
	 * reader fast path will be available again. Safe to use outside the
	 * exclusive write lock because its counting.
	 */
	rcu_sync_exit(&sem->rss);
}
EXPORT_SYMBOL_GPL(percpu_up_write);
