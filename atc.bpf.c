// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

unsigned long tgidpid = 0;
unsigned long cgid = 0;
unsigned long allret = 0;

#define INVALID_RET ((unsigned long) -1L)

//#define debug(args...) bpf_printk(args)
#define debug(args...)

SEC("sched/cfs_check_preempt_wakeup")
int BPF_PROG(wakeup, struct task_struct *curr, struct task_struct *p)
{
	unsigned long tgidpid1, tgidpid2;
	int ret = 0;

	if (allret)
		return allret;

	if (tgidpid) {
		tgidpid1 = (unsigned long)curr->tgid << 32 | curr->pid;
		tgidpid2 = (unsigned long)p->tgid << 32 | p->pid;

		if ((tgidpid1 & tgidpid) == tgidpid)
			ret = -1;
		else if ((tgidpid2 & tgidpid) == tgidpid)
			ret = 1;

		if (ret) {
			debug("wakeup1 tgid %d pid %d", tgidpid1 >> 32,
				   tgidpid1 & 0xFFFFFFFF);
			debug("wakeup2 tgid %d pid %d", tgidpid2 >> 32,
				   tgidpid2 & 0xFFFFFFFF);
			debug("wakeup ret %d", ret);
		}
	} else if (cgid) {
		if (bpf_sched_entity_belongs_to_cgrp(&curr->se, cgid))
			ret = -1;
		else if (bpf_sched_entity_belongs_to_cgrp(&p->se, cgid))
			ret = 1;

		if (ret) {
			debug("wakeup1 tgid %d pid %d", tgidpid1 >> 32,
				   tgidpid1 & 0xFFFFFFFF);
			debug("wakeup2 tgid %d pid %d", tgidpid2 >> 32,
				   tgidpid2 & 0xFFFFFFFF);
			debug("wakeup ret %d", ret);
		}
	}

	return ret;
}

SEC("sched/cfs_check_preempt_tick")
int BPF_PROG(tick, struct sched_entity *curr, unsigned long delta_exec)
{
	unsigned long tgidpid1;
	int ret = 0;

	if (allret)
		return allret;

	if (curr == NULL)
		return 0;

	/* pid/tgid mode */
	if (tgidpid) {
		tgidpid1 = bpf_sched_entity_to_tgidpid(curr);

		if ((tgidpid1 & tgidpid) == tgidpid)
			ret = -1;

		if (ret)
			debug("tick tgid %d pid %d ret %d", tgidpid1 >> 32,
				   tgidpid1 & 0xFFFFFFFF, ret);

	/* cgroup id mode */
	} else if (cgid) {
		if (bpf_sched_entity_belongs_to_cgrp(curr, cgid)) {
			ret = -1;
			debug("tick cg %lu %d", bpf_sched_entity_to_cgrpid(curr), ret);
		}
	}

	return ret;
}

SEC("sched/cfs_wakeup_preempt_entity")
int BPF_PROG(preempt_entity, struct sched_entity *curr, struct sched_entity *se)
{
	int ret = 0;

	if (allret)
		return allret;

	if (curr == NULL || se == NULL)
		return 0;

	/* pid/tgid mode */
	if (tgidpid) {
		unsigned long tgidpid1, tgidpid2;

		tgidpid1 = bpf_sched_entity_to_tgidpid(curr);
		tgidpid2 = bpf_sched_entity_to_tgidpid(se);

		if ((tgidpid1 & tgidpid) == tgidpid)
			ret = -1;
		else if ((tgidpid2 & tgidpid) == tgidpid)
			ret = 1;

		if (ret) {
			debug("entity1 tgid %d pid %d", tgidpid1 >> 32,
				   tgidpid1 & 0xFFFFFFFF);
			debug("entity2 tgid %d pid %d", tgidpid2 >> 32,
				   tgidpid2 & 0xFFFFFFFF);
			debug("entity ret %d", ret);
		}

	/* cgroup id mode */
	} else if (cgid) {
		if (bpf_sched_entity_belongs_to_cgrp(curr, cgid))
			ret = -1;
		else if (bpf_sched_entity_belongs_to_cgrp(se, cgid))
			ret = 1;

		if (ret) {
			debug("entity cg %lu", bpf_sched_entity_to_cgrpid(curr));
			debug("entity cg %lu", bpf_sched_entity_to_cgrpid(se));
			debug("entity cg %d", ret);
		}
	}

	return ret;
}
