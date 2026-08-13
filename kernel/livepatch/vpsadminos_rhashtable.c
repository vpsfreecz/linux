// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/memory.h>
#include <linux/rcupdate.h>
#include <linux/rhashtable.h>
#include <linux/string.h>
#include <linux/vpsadminos-livepatch.h>

#include <asm/text-patching.h>

#define VPSADMINOS_RHASHTABLE_STATE_ID		0x8173f7e2ce67e6caUL
#define VPSADMINOS_RHASHTABLE_STATE_VERSION	1

union vpsadminos_rhashtable_block {
	u64 word;
	u8 text[sizeof(u64)];
};

static const union vpsadminos_rhashtable_block
vpsadminos_rhashtable_boot_entry = {
	.text = { 0x55, 0x48, 0x89, 0xe5, 0x41, 0x56, 0x41, 0x55 },
};

struct vpsadminos_rhashtable_transition {
	u64 original;
	u64 patched;
};

static struct klp_state vpsadminos_rhashtable_state
__section(".kpatch.system_states") __used
__aligned(__alignof__(struct klp_state)) = {
	.id = VPSADMINOS_RHASHTABLE_STATE_ID,
	.version = VPSADMINOS_RHASHTABLE_STATE_VERSION,
};

static struct vpsadminos_rhashtable_transition
vpsadminos_rhashtable_transition;
static struct vpsadminos_rhashtable_transition
*vpsadminos_rhashtable_predecessor;
static u64 vpsadminos_rhashtable_previous;
static bool vpsadminos_rhashtable_text_patched;

noinline int
vpsadminos_rhashtable_walk_start_check(struct rhashtable_iter *iter)
	__acquires(RCU)
{
	struct rhashtable *ht = iter->ht;
	bool rhlist = ht->rhlist;

	rcu_read_lock();

	spin_lock(&ht->lock);
	if (iter->walker.tbl)
		list_del(&iter->walker.list);
	spin_unlock(&ht->lock);

	if (iter->end_of_table)
		return 0;
	if (!iter->walker.tbl) {
		iter->walker.tbl = rht_dereference_rcu(ht->tbl, ht);
		iter->slot = 0;
		iter->skip = 0;
		iter->p = NULL;
		return -EAGAIN;
	}

	if (iter->p && !rhlist) {
		struct rhash_head *p;
		int skip = 0;

		rht_for_each_rcu(p, iter->walker.tbl, iter->slot) {
			skip++;
			if (p == iter->p) {
				iter->skip = skip;
				goto found;
			}
		}
		iter->p = NULL;
	} else if (iter->p && rhlist) {
		struct rhash_head *p;
		struct rhlist_head *list;
		int skip = 0;

		rht_for_each_rcu(p, iter->walker.tbl, iter->slot) {
			for (list = container_of(p, struct rhlist_head, rhead);
			     list;
			     list = rcu_dereference(list->next)) {
				skip++;
				if (list == iter->list) {
					iter->p = p;
					iter->skip = skip;
					goto found;
				}
			}
		}
		iter->p = NULL;
	}
found:
	return 0;
}

static int vpsadminos_rhashtable_make_jump(u8 *text, void *target)
{
	void *site = rhashtable_walk_start_check;
	union text_poke_insn insn;
	s64 displacement = (s64)(unsigned long)target -
			   ((s64)(unsigned long)site + JMP32_INSN_SIZE);

	if (displacement != (s64)(s32)displacement)
		return -ERANGE;

	__text_gen_insn(&insn, JMP32_INSN_OPCODE, site, target,
			JMP32_INSN_SIZE);
	memcpy(text, insn.text, JMP32_INSN_SIZE);
	return 0;
}

int vpsadminos_rhashtable_livepatch_pre_patch(void)
{
	struct vpsadminos_rhashtable_transition *prev_transition = NULL;
	struct klp_state *prev_state;
	union vpsadminos_rhashtable_block expected;
	union vpsadminos_rhashtable_block patched;
	void *site = rhashtable_walk_start_check;
	void *target = vpsadminos_rhashtable_walk_start_check;
	int ret;

	if (vpsadminos_rhashtable_text_patched)
		return -EBUSY;

	prev_state = klp_get_prev_state(VPSADMINOS_RHASHTABLE_STATE_ID);
	if (prev_state) {
		if (prev_state->version != VPSADMINOS_RHASHTABLE_STATE_VERSION) {
			pr_err("livepatch rhashtable predecessor state version %u is incompatible\n",
			       prev_state->version);
			return -EINVAL;
		}
		prev_transition = READ_ONCE(prev_state->data);
	}

	if (prev_transition) {
		expected.word = READ_ONCE(prev_transition->patched);
		vpsadminos_rhashtable_transition.original =
			READ_ONCE(prev_transition->original);
	} else {
		expected = vpsadminos_rhashtable_boot_entry;
		vpsadminos_rhashtable_transition.original = expected.word;
	}

	memset(patched.text, 0x90, sizeof(patched.text));
	ret = vpsadminos_rhashtable_make_jump(patched.text, target);
	if (ret)
		return ret;

	vpsadminos_rhashtable_previous = expected.word;
	vpsadminos_rhashtable_transition.patched = patched.word;
	vpsadminos_rhashtable_predecessor = prev_transition;

	ret = vpsadminos_livepatch_text_poke_cmpxchg64(site, expected.word, patched.word);
	if (ret) {
		pr_err("livepatch rhashtable entry text does not match 6.12.95\n");
		return ret;
	}
	vpsadminos_rhashtable_text_patched = true;

	return 0;
}

void vpsadminos_rhashtable_livepatch_post_patch(void)
{
	struct klp_state *prev_state;

	if (!vpsadminos_rhashtable_text_patched)
		return;

	WRITE_ONCE(vpsadminos_rhashtable_state.data,
		   &vpsadminos_rhashtable_transition);
	/* No new entry can reach predecessor text after the installed jump. */
	synchronize_rcu_tasks();
	prev_state = klp_get_prev_state(VPSADMINOS_RHASHTABLE_STATE_ID);
	if (prev_state &&
	    READ_ONCE(prev_state->data) == vpsadminos_rhashtable_predecessor)
		WRITE_ONCE(prev_state->data, NULL);
}

void vpsadminos_rhashtable_livepatch_post_unpatch(void)
{
	u64 patched;
	u64 restore;
	bool committed;
	void *site = rhashtable_walk_start_check;
	int ret;

	committed = READ_ONCE(vpsadminos_rhashtable_state.data) ==
		    &vpsadminos_rhashtable_transition;
	if (!vpsadminos_rhashtable_text_patched)
		return;

	if (committed)
		restore = vpsadminos_rhashtable_transition.original;
	else
		restore = vpsadminos_rhashtable_previous;

	patched = vpsadminos_rhashtable_transition.patched;
	ret = vpsadminos_livepatch_text_poke_cmpxchg64(site, patched, restore);
	if (ret)
		panic("livepatch rhashtable cannot safely restore entry text");

	/* Drain callers redirected before the restoration completed. */
	synchronize_rcu_tasks();
	vpsadminos_rhashtable_text_patched = false;
	vpsadminos_rhashtable_predecessor = NULL;
	WRITE_ONCE(vpsadminos_rhashtable_state.data, NULL);
}
