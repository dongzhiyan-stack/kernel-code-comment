/*
 *  Block device elevator/IO-scheduler.
 *
 *  Copyright (C) 2000 Andrea Arcangeli <andrea@suse.de> SuSE
 *
 * 30042000 Jens Axboe <axboe@kernel.dk> :
 *
 * Split the elevator a bit so that it is possible to choose a different
 * one or even write a new "plug in". There are three pieces:
 * - elevator_fn, inserts a new request in the queue list
 * - elevator_merge_fn, decides whether a new buffer can be merged with
 *   an existing request
 * - elevator_dequeue_fn, called when a request is taken off the active list
 *
 * 20082000 Dave Jones <davej@suse.de> :
 * Removed tests for max-bomb-segments, which was breaking elvtune
 *  when run without -bN
 *
 * Jens:
 * - Rework again to work with bio instead of buffer_heads
 * - loose bi_dev comparisons, partition handling is right now
 * - completely modularize elevator setup and teardown
 *
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/blktrace_api.h>
#include <linux/hash.h>
#include <linux/uaccess.h>
#include <linux/pm_runtime.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-cgroup.h"
#include "blk-mq-sched.h"

static DEFINE_SPINLOCK(elv_list_lock);
static LIST_HEAD(elv_list);
static LIST_HEAD(elv_aux_list);

/*
 * Merge hash stuff.
 */
#define rq_hash_key(rq)		(blk_rq_pos(rq) + blk_rq_sectors(rq))

static struct elevator_type_aux *__elevator_aux_find(const struct elevator_type *e)
{
	struct elevator_type_aux *e_aux;

	list_for_each_entry(e_aux, &elv_aux_list, list) {
		if (e_aux->type == e)
			return e_aux;
	}
	return NULL;
}

struct elevator_type_aux *elevator_aux_find(struct elevator_type *e)
{
	struct elevator_type_aux *e_aux;

	spin_lock(&elv_list_lock);
	e_aux = __elevator_aux_find(e);
	spin_unlock(&elv_list_lock);

	return e_aux;
}
EXPORT_SYMBOL(elevator_aux_find);

/*
 * Query io scheduler to see if the current process issuing bio may be
 * merged with rq.
 */
static int elv_iosched_allow_bio_merge(struct request *rq, struct bio *bio)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (e->uses_mq && e->aux->ops.mq.allow_merge)
		return e->aux->ops.mq.allow_merge(q, rq, bio);
	else if (!e->uses_mq && e->aux->ops.sq.elevator_allow_bio_merge_fn)
		return e->aux->ops.sq.elevator_allow_bio_merge_fn(q, rq, bio);

	return 1;
}

/*
 * can we safely merge with this request?
 */
bool elv_bio_merge_ok(struct request *rq, struct bio *bio)
{
	if (!blk_rq_merge_ok(rq, bio))
		return false;

	if (!elv_iosched_allow_bio_merge(rq, bio))
		return false;

	return true;
}
EXPORT_SYMBOL(elv_bio_merge_ok);

bool elv_rq_merge_ok(struct request *rq, struct bio *bio)
{
	return elv_bio_merge_ok(rq, bio);
}
EXPORT_SYMBOL(elv_rq_merge_ok);

/* called when elv_list_lock is held */
static bool __elevator_match(const struct elevator_type *e, const char *name)
{
	struct elevator_type_aux *aux;

	if (!strcmp(e->elevator_name, name))
		return true;

	aux = __elevator_aux_find(e);
	if (!aux)
		return false;

	if (aux->elevator_alias && !strcmp(aux->elevator_alias, name))
		return true;

	return false;
}

/* called when elv_list_lock isn't held */
static bool elevator_match(const struct elevator_type *e, const char *name)
{
	bool ret;

	spin_lock(&elv_list_lock);
	ret = __elevator_match(e, name);
	spin_unlock(&elv_list_lock);

	return ret;
}

/*
 * Return scheduler with name 'name' and with matching 'mq capability
 */
static struct elevator_type *elevator_find(const char *name, bool mq)
{
	struct elevator_type *e;

	list_for_each_entry(e, &elv_list, list) {
		if (__elevator_match(e, name) &&
				(mq == !e->ops.elevator_init_fn))
			return e;
	}

	return NULL;
}

static void elevator_put(struct elevator_type *e)
{
	module_put(e->elevator_owner);
}

static struct elevator_type *elevator_get(struct request_queue *q,
					  const char *name, bool try_loading)
{
	struct elevator_type *e;

	spin_lock(&elv_list_lock);

	e = elevator_find(name, q->mq_ops != NULL);
	if (!e && try_loading) {
		spin_unlock(&elv_list_lock);
		request_module("%s-iosched", name);
		spin_lock(&elv_list_lock);
		e = elevator_find(name, q->mq_ops != NULL);
	}

	if (e && !try_module_get(e->elevator_owner))
		e = NULL;

	spin_unlock(&elv_list_lock);
	return e;
}

char chosen_elevator[ELV_NAME_MAX];
EXPORT_SYMBOL(chosen_elevator);

static int __init elevator_setup(char *str)
{
	/*
	 * Be backwards-compatible with previous kernels, so users
	 * won't get the wrong elevator.
	 */
	strncpy(chosen_elevator, str, sizeof(chosen_elevator) - 1);
	return 1;
}

__setup("elevator=", elevator_setup);

/* called during boot to load the elevator chosen by the elevator param */
void __init load_default_elevator_module(void)
{
	struct elevator_type *e;

	if (!chosen_elevator[0])
		return;

	/*
	 * Boot parameter is deprecated, we haven't supported that for MQ.
	 * Only look for non-mq schedulers from here.
	 */
	spin_lock(&elv_list_lock);
	e = elevator_find(chosen_elevator, false);
	spin_unlock(&elv_list_lock);

	if (!e)
		request_module("%s-iosched", chosen_elevator);
}

static struct kobj_type elv_ktype;

struct elevator_queue *elevator_alloc(struct request_queue *q,
				  struct elevator_type *e)
{
	struct elevator_queue *eq;

	eq = kmalloc_node(sizeof(*eq), GFP_KERNEL | __GFP_ZERO, q->node);
	if (unlikely(!eq))
		goto err;

	eq->type = e;
	eq->aux = elevator_aux_find(e);
	if (!eq->aux)
		goto err;
	kobject_init(&eq->kobj, &elv_ktype);
	mutex_init(&eq->sysfs_lock);
	hash_init(eq->hash);
	eq->uses_mq = eq->aux->uses_mq;

	return eq;
err:
	kfree(eq);
	elevator_put(e);
	return NULL;
}
EXPORT_SYMBOL(elevator_alloc);

static void elevator_release(struct kobject *kobj)
{
	struct elevator_queue *e;

	e = container_of(kobj, struct elevator_queue, kobj);
	elevator_put(e->type);
	kfree(e);
}

int elevator_init(struct request_queue *q, char *name)
{
	struct elevator_type *e = NULL;
	int err;
	struct elevator_type_aux *aux;

	/*
	 * q->sysfs_lock must be held to provide mutual exclusion between
	 * elevator_switch() and here.
	 */
	lockdep_assert_held(&q->sysfs_lock);

	if (unlikely(q->elevator))
		return 0;

	INIT_LIST_HEAD(&q->queue_head);
	q->last_merge = NULL;
	q->end_sector = 0;
	q->boundary_rq = NULL;

	if (name) {
		e = elevator_get(q, name, true);
		if (!e)
			return -EINVAL;
	}

	/*
	 * Use the default elevator specified by config boot param for
	 * non-mq devices, or by config option. Don't try to load modules
	 * as we could be running off async and request_module() isn't
	 * allowed from async.
	 */
	if (!e && !q->mq_ops && *chosen_elevator) {
		e = elevator_get(q, chosen_elevator, false);
		if (!e)
			printk(KERN_ERR "I/O scheduler %s not found\n",
							chosen_elevator);
	}

	if (!e) {
		/*
		 * For blk-mq devices, we default to using mq-deadline,
		 * if available, for single queue devices. If deadline
		 * isn't available OR we have multiple queues, default
		 * to "none".
		 */
		if (q->mq_ops) {
			if (q->nr_hw_queues == 1)
				e = elevator_get(q, "mq-deadline", false);
			if (!e)
				return 0;
		} else
			e = elevator_get(q, CONFIG_DEFAULT_IOSCHED, false);

		if (!e) {
			printk(KERN_ERR
				"Default I/O scheduler not found. " \
				"Using noop.\n");
			e = elevator_get(q, "noop", false);
		}
	}

	aux = elevator_aux_find(e);
	if (aux->uses_mq)
		err = blk_mq_init_sched(q, e);
	else
		err = aux->ops.sq.elevator_init_fn(q, e);
	if (err)
		elevator_put(e);
	return err;
}
EXPORT_SYMBOL(elevator_init);

void elevator_exit(struct request_queue *q, struct elevator_queue *e)
{
	mutex_lock(&e->sysfs_lock);
	if (e->uses_mq && e->aux->ops.mq.exit_sched)
		blk_mq_exit_sched(q, e);
	else if (!e->uses_mq && e->aux->ops.sq.elevator_exit_fn)
		e->aux->ops.sq.elevator_exit_fn(e);
	mutex_unlock(&e->sysfs_lock);

	kobject_put(&e->kobj);
}
EXPORT_SYMBOL(elevator_exit);

static inline void __elv_rqhash_del(struct request *rq)
{
	hash_del(&rq->hash);
	rq->cmd_flags &= ~REQ_HASHED;
}

void elv_rqhash_del(struct request_queue *q, struct request *rq)
{
	if (ELV_ON_HASH(rq))
		__elv_rqhash_del(rq);
}
EXPORT_SYMBOL_GPL(elv_rqhash_del);

void elv_rqhash_add(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	BUG_ON(ELV_ON_HASH(rq));
	hash_add(e->hash, &rq->hash, rq_hash_key(rq));
	rq->cmd_flags |= REQ_HASHED;
}
EXPORT_SYMBOL_GPL(elv_rqhash_add);

void elv_rqhash_reposition(struct request_queue *q, struct request *rq)
{
	__elv_rqhash_del(rq);
	elv_rqhash_add(q, rq);
}

struct request *elv_rqhash_find(struct request_queue *q, sector_t offset)
{
	struct elevator_queue *e = q->elevator;
	struct hlist_node *next;
	struct request *rq;

	hash_for_each_possible_safe(e->hash, rq, next, hash, offset) {
		BUG_ON(!ELV_ON_HASH(rq));

		if (unlikely(!rq_mergeable(rq))) {
			__elv_rqhash_del(rq);
			continue;
		}

		if (rq_hash_key(rq) == offset)
			return rq;
	}

	return NULL;
}

/*
 * RB-tree support functions for inserting/lookup/removal of requests
 * in a sorted RB tree.
 */
void elv_rb_add(struct rb_root *root, struct request *rq)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct request *__rq;

	while (*p) {
		parent = *p;
		__rq = rb_entry(parent, struct request, rb_node);

		if (blk_rq_pos(rq) < blk_rq_pos(__rq))
			p = &(*p)->rb_left;
		else if (blk_rq_pos(rq) >= blk_rq_pos(__rq))
			p = &(*p)->rb_right;
	}

	rb_link_node(&rq->rb_node, parent, p);
	rb_insert_color(&rq->rb_node, root);
}
EXPORT_SYMBOL(elv_rb_add);

void elv_rb_del(struct rb_root *root, struct request *rq)
{
	BUG_ON(RB_EMPTY_NODE(&rq->rb_node));
	rb_erase(&rq->rb_node, root);
	RB_CLEAR_NODE(&rq->rb_node);
}
EXPORT_SYMBOL(elv_rb_del);

struct request *elv_rb_find(struct rb_root *root, sector_t sector)
{
	struct rb_node *n = root->rb_node;
	struct request *rq;

	while (n) {
		rq = rb_entry(n, struct request, rb_node);

		if (sector < blk_rq_pos(rq))
			n = n->rb_left;
		else if (sector > blk_rq_pos(rq))
			n = n->rb_right;
		else
			return rq;
	}

	return NULL;
}
EXPORT_SYMBOL(elv_rb_find);

/*
 * Insert rq into dispatch queue of q.  Queue lock must be held on
 * entry.  rq is sort instead into the dispatch queue. To be used by
 * specific elevators.
 */
void elv_dispatch_sort(struct request_queue *q, struct request *rq)
{
	sector_t boundary;
	struct list_head *entry;
	int stop_flags;

	if (q->last_merge == rq)
		q->last_merge = NULL;

	elv_rqhash_del(q, rq);

	q->nr_sorted--;

	boundary = q->end_sector;
	stop_flags = REQ_SOFTBARRIER | REQ_STARTED;
	list_for_each_prev(entry, &q->queue_head) {
		struct request *pos = list_entry_rq(entry);

		if ((rq->cmd_flags & REQ_DISCARD) !=
		    (pos->cmd_flags & REQ_DISCARD))
			break;
		if (rq_data_dir(rq) != rq_data_dir(pos))
			break;
		if (pos->cmd_flags & stop_flags)
			break;
		if (blk_rq_pos(rq) >= boundary) {
			if (blk_rq_pos(pos) < boundary)
				continue;
		} else {
			if (blk_rq_pos(pos) >= boundary)
				break;
		}
		if (blk_rq_pos(rq) >= blk_rq_pos(pos))
			break;
	}

	list_add(&rq->queuelist, entry);
}
EXPORT_SYMBOL(elv_dispatch_sort);

/*
 * Insert rq into dispatch queue of q.  Queue lock must be held on
 * entry.  rq is added to the back of the dispatch queue. To be used by
 * specific elevators.
 */
void elv_dispatch_add_tail(struct request_queue *q, struct request *rq)
{
	if (q->last_merge == rq)
		q->last_merge = NULL;

	elv_rqhash_del(q, rq);

	q->nr_sorted--;

	q->end_sector = rq_end_sector(rq);
	q->boundary_rq = rq;
	list_add_tail(&rq->queuelist, &q->queue_head);
}
EXPORT_SYMBOL(elv_dispatch_add_tail);

int elv_merge(struct request_queue *q, struct request **req, struct bio *bio)
{
	struct elevator_queue *e = q->elevator;
	struct request *__rq;
	int ret;

	/*
	 * Levels of merges:
	 * 	nomerges:  No merges at all attempted
	 * 	noxmerges: Only simple one-hit cache try
	 * 	merges:	   All merge tries attempted
	 */
	if (blk_queue_nomerges(q))
		return ELEVATOR_NO_MERGE;

	/*
	 * First try one-hit cache.
	 */
	if (q->last_merge && elv_bio_merge_ok(q->last_merge, bio)) {
		ret = blk_try_merge(q->last_merge, bio);
		if (ret != ELEVATOR_NO_MERGE) {
			*req = q->last_merge;
			return ret;
		}
	}

	if (blk_queue_noxmerges(q))
		return ELEVATOR_NO_MERGE;

	/*
	 * See if our hash lookup can find a potential backmerge.
	 */
	__rq = elv_rqhash_find(q, bio->bi_sector);
	if (__rq && elv_bio_merge_ok(__rq, bio)) {
		*req = __rq;
		return ELEVATOR_BACK_MERGE;
	}

	if (e->uses_mq && e->aux->ops.mq.request_merge)
		return e->aux->ops.mq.request_merge(q, req, bio);
	else if (!e->uses_mq && e->aux->ops.sq.elevator_merge_fn)
		return e->aux->ops.sq.elevator_merge_fn(q, req, bio);

	return ELEVATOR_NO_MERGE;
}

/*
 * Attempt to do an insertion back merge. Only check for the case where
 * we can append 'rq' to an existing request, so we can throw 'rq' away
 * afterwards.
 *
 * Returns true if we merged, false otherwise
 */
bool elv_attempt_insert_merge(struct request_queue *q, struct request *rq)
{
	struct request *__rq;
	bool ret;

	if (blk_queue_nomerges(q))
		return false;

	/*
	 * First try one-hit cache.
	 */
	if (q->last_merge && blk_attempt_req_merge(q, q->last_merge, rq))
		return true;

	if (blk_queue_noxmerges(q))
		return false;

	ret = false;
	/*
	 * See if our hash lookup can find a potential backmerge.
	 */
	while (1) {
		__rq = elv_rqhash_find(q, blk_rq_pos(rq));
		if (!__rq || !blk_attempt_req_merge(q, __rq, rq))
			break;

		/* The merged request could be merged with others, try again */
		ret = true;
		rq = __rq;
	}

	return ret;
}

void elv_merged_request(struct request_queue *q, struct request *rq, int type)
{
	struct elevator_queue *e = q->elevator;

	if (e->uses_mq && e->aux->ops.mq.request_merged)
		e->aux->ops.mq.request_merged(q, rq, type);
	else if (!e->uses_mq && e->aux->ops.sq.elevator_merged_fn)
		e->aux->ops.sq.elevator_merged_fn(q, rq, type);

	if (type == ELEVATOR_BACK_MERGE)
		elv_rqhash_reposition(q, rq);

	q->last_merge = rq;
}

void elv_merge_requests(struct request_queue *q, struct request *rq,
			     struct request *next)
{
	struct elevator_queue *e = q->elevator;

	bool next_sorted = false;

	if (e->uses_mq && e->aux->ops.mq.requests_merged)
        //在fifo队列里，把req移动到next节点的位置，更新req的超时时间。从fifo队列和红黑树剔除next,还更新dd->next_rq[]赋值next的下一个req
		e->aux->ops.mq.requests_merged(q, rq, next);//dd_merged_requests
	else if (e->aux->ops.sq.elevator_merge_req_fn) {
		next_sorted = (__force bool)(next->cmd_flags & REQ_SORTED);
		if (next_sorted)
			e->aux->ops.sq.elevator_merge_req_fn(q, rq, next);
	}

	elv_rqhash_reposition(q, rq);

	if (next_sorted) {
		elv_rqhash_del(q, next);
		q->nr_sorted--;
	}

	q->last_merge = rq;
}

void elv_bio_merged(struct request_queue *q, struct request *rq,
			struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (WARN_ON_ONCE(e->uses_mq))
		return;

	if (e->aux->ops.sq.elevator_bio_merged_fn)
		e->aux->ops.sq.elevator_bio_merged_fn(q, rq, bio);
}

#ifdef CONFIG_PM_RUNTIME
static void blk_pm_requeue_request(struct request *rq)
{
	if (rq->q->dev && !(rq->cmd_flags & REQ_PM))
		rq->q->nr_pending--;
}

static void blk_pm_add_request(struct request_queue *q, struct request *rq)
{
	if (q->dev && !(rq->cmd_flags & REQ_PM) && q->nr_pending++ == 0 &&
	    (q->rpm_status == RPM_SUSPENDED || q->rpm_status == RPM_SUSPENDING))
		pm_request_resume(q->dev);
}
#else
static inline void blk_pm_requeue_request(struct request *rq) {}
static inline void blk_pm_add_request(struct request_queue *q,
				      struct request *rq)
{
}
#endif

void elv_requeue_request(struct request_queue *q, struct request *rq)
{
	/*
	 * it already went through dequeue, we need to decrement the
	 * in_flight count again
	 */
	if (blk_account_rq(rq)) {
		q->in_flight[rq_is_sync(rq)]--;
		if (rq->cmd_flags & REQ_SORTED)
			elv_deactivate_rq(q, rq);
	}

	rq->cmd_flags &= ~REQ_STARTED;

	blk_pm_requeue_request(rq);

	__elv_add_request(q, rq, ELEVATOR_INSERT_REQUEUE);
}

void elv_drain_elevator(struct request_queue *q)
{
	struct elevator_queue *e = q->elevator;
	static int printed;

	if (WARN_ON_ONCE(e->uses_mq))
		return;

	lockdep_assert_held(q->queue_lock);

	while (e->aux->ops.sq.elevator_dispatch_fn(q, 1))
		;
	if (q->nr_sorted && printed++ < 10) {
		printk(KERN_ERR "%s: forced dispatching is broken "
		       "(nr_sorted=%u), please report this\n",
		       q->elevator->type->elevator_name, q->nr_sorted);
	}
}

void __elv_add_request(struct request_queue *q, struct request *rq, int where)
{
	trace_block_rq_insert(q, rq);

	blk_pm_add_request(q, rq);

	rq->q = q;

	if (rq->cmd_flags & REQ_SOFTBARRIER) {
		/* barriers are scheduling boundary, update end_sector */
		if (rq->cmd_type == REQ_TYPE_FS) {
			q->end_sector = rq_end_sector(rq);
			q->boundary_rq = rq;
		}
	} else if (!(rq->cmd_flags & REQ_ELVPRIV) &&
		    (where == ELEVATOR_INSERT_SORT ||
		     where == ELEVATOR_INSERT_SORT_MERGE))
		where = ELEVATOR_INSERT_BACK;

	switch (where) {
	case ELEVATOR_INSERT_REQUEUE:
	case ELEVATOR_INSERT_FRONT:
		rq->cmd_flags |= REQ_SOFTBARRIER;
		list_add(&rq->queuelist, &q->queue_head);
		break;

	case ELEVATOR_INSERT_BACK:
		rq->cmd_flags |= REQ_SOFTBARRIER;
		elv_drain_elevator(q);
		list_add_tail(&rq->queuelist, &q->queue_head);
		/*
		 * We kick the queue here for the following reasons.
		 * - The elevator might have returned NULL previously
		 *   to delay requests and returned them now.  As the
		 *   queue wasn't empty before this request, ll_rw_blk
		 *   won't run the queue on return, resulting in hang.
		 * - Usually, back inserted requests won't be merged
		 *   with anything.  There's no point in delaying queue
		 *   processing.
		 */
		__blk_run_queue(q);
		break;

	case ELEVATOR_INSERT_SORT_MERGE:
		/*
		 * If we succeed in merging this request with one in the
		 * queue already, we are done - rq has now been freed,
		 * so no need to do anything further.
		 */
		if (elv_attempt_insert_merge(q, rq))
			break;
	case ELEVATOR_INSERT_SORT:
		BUG_ON(rq->cmd_type != REQ_TYPE_FS);
		rq->cmd_flags |= REQ_SORTED;
		q->nr_sorted++;
		if (rq_mergeable(rq)) {
			elv_rqhash_add(q, rq);
			if (!q->last_merge)
				q->last_merge = rq;
		}

		/*
		 * Some ioscheds (cfq) run q->request_fn directly, so
		 * rq cannot be accessed after calling
		 * elevator_add_req_fn.
		 */
		q->elevator->aux->ops.sq.elevator_add_req_fn(q, rq);
		break;

	case ELEVATOR_INSERT_FLUSH:
		rq->cmd_flags |= REQ_SOFTBARRIER;
		blk_insert_flush(rq);
		break;
	default:
		printk(KERN_ERR "%s: bad insertion point %d\n",
		       __func__, where);
		BUG();
	}
}
EXPORT_SYMBOL(__elv_add_request);

void elv_add_request(struct request_queue *q, struct request *rq, int where)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	__elv_add_request(q, rq, where);
	spin_unlock_irqrestore(q->queue_lock, flags);
}
EXPORT_SYMBOL(elv_add_request);

struct request *elv_latter_request(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (e->uses_mq && e->aux->ops.mq.next_request)
		return e->aux->ops.mq.next_request(q, rq);//elv_rb_latter_request
	else if (!e->uses_mq && e->aux->ops.sq.elevator_latter_req_fn)
		return e->aux->ops.sq.elevator_latter_req_fn(q, rq);//elv_rb_latter_request

	return NULL;
}

struct request *elv_former_request(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (e->uses_mq && e->aux->ops.mq.former_request)
		return e->aux->ops.mq.former_request(q, rq);
	if (!e->uses_mq && e->aux->ops.sq.elevator_former_req_fn)
		return e->aux->ops.sq.elevator_former_req_fn(q, rq);
	return NULL;
}

int elv_set_request(struct request_queue *q, struct request *rq,
		    struct bio *bio, gfp_t gfp_mask)
{
	struct elevator_queue *e = q->elevator;

	if (WARN_ON_ONCE(e->uses_mq))
		return 0;

	if (e->aux->ops.sq.elevator_set_req_fn)
		return e->aux->ops.sq.elevator_set_req_fn(q, rq, bio, gfp_mask);
	return 0;
}

void elv_put_request(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (WARN_ON_ONCE(e->uses_mq))
		return;

	if (e->aux->ops.sq.elevator_put_req_fn)
		e->aux->ops.sq.elevator_put_req_fn(rq);
}

int elv_may_queue(struct request_queue *q, int rw)
{
	struct elevator_queue *e = q->elevator;

	if (WARN_ON_ONCE(e->uses_mq))
		return 0;

	if (e->aux->ops.sq.elevator_may_queue_fn)
		return e->aux->ops.sq.elevator_may_queue_fn(q, rw);

	return ELV_MQUEUE_MAY;
}

void elv_completed_request(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (WARN_ON_ONCE(e->uses_mq))
		return;

	/*
	 * request is released from the driver, io must be done
	 */
	if (blk_account_rq(rq)) {
		q->in_flight[rq_is_sync(rq)]--;
		if ((rq->cmd_flags & REQ_SORTED) &&
		    e->aux->ops.sq.elevator_completed_req_fn)
			e->aux->ops.sq.elevator_completed_req_fn(q, rq);
	}
}

#define to_elv(atr) container_of((atr), struct elv_fs_entry, attr)

static ssize_t
elv_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct elv_fs_entry *entry = to_elv(attr);
	struct elevator_queue *e;
	ssize_t error;

	if (!entry->show)
		return -EIO;

	e = container_of(kobj, struct elevator_queue, kobj);
	mutex_lock(&e->sysfs_lock);
	error = e->type ? entry->show(e, page) : -ENOENT;
	mutex_unlock(&e->sysfs_lock);
	return error;
}

static ssize_t
elv_attr_store(struct kobject *kobj, struct attribute *attr,
	       const char *page, size_t length)
{
	struct elv_fs_entry *entry = to_elv(attr);
	struct elevator_queue *e;
	ssize_t error;

	if (!entry->store)
		return -EIO;

	e = container_of(kobj, struct elevator_queue, kobj);
	mutex_lock(&e->sysfs_lock);
	error = e->type ? entry->store(e, page, length) : -ENOENT;
	mutex_unlock(&e->sysfs_lock);
	return error;
}

static const struct sysfs_ops elv_sysfs_ops = {
	.show	= elv_attr_show,
	.store	= elv_attr_store,
};

static struct kobj_type elv_ktype = {
	.sysfs_ops	= &elv_sysfs_ops,
	.release	= elevator_release,
};

int elv_register_queue(struct request_queue *q)
{
	struct elevator_queue *e = q->elevator;
	int error;

	error = kobject_add(&e->kobj, &q->kobj, "%s", "iosched");
	if (!error) {
		struct elv_fs_entry *attr = e->type->elevator_attrs;
		if (attr) {
			while (attr->attr.name) {
				if (sysfs_create_file(&e->kobj, &attr->attr))
					break;
				attr++;
			}
		}
		kobject_uevent(&e->kobj, KOBJ_ADD);
		e->registered = 1;
		if (!e->uses_mq && e->aux->ops.sq.elevator_registered_fn)
			e->aux->ops.sq.elevator_registered_fn(q);
	}
	return error;
}
EXPORT_SYMBOL(elv_register_queue);

void elv_unregister_queue(struct request_queue *q)
{
	if (q) {
		struct elevator_queue *e = q->elevator;

		kobject_uevent(&e->kobj, KOBJ_REMOVE);
		kobject_del(&e->kobj);
		e->registered = 0;
	}
}
EXPORT_SYMBOL(elv_unregister_queue);

static int elv_aux_register(struct elevator_type *e)
{
	struct elevator_type_aux *e_aux;

	e_aux = kzalloc(sizeof(*e_aux), GFP_KERNEL);
	if (!e_aux)
		goto fail;

	e_aux->type = e;
	memcpy(&e_aux->ops.sq, &e->ops, sizeof(struct elevator_ops));
	spin_lock(&elv_list_lock);
	list_add_tail(&e_aux->list, &elv_aux_list);
	spin_unlock(&elv_list_lock);

	return 0;
 fail:
	elv_unregister(e);
	return -ENOMEM;
}

static void elv_aux_unregister(struct elevator_type *e)
{
	struct elevator_type_aux *e_aux;

	spin_lock(&elv_list_lock);
	e_aux = __elevator_aux_find(e);
	if (e_aux)
		list_del_init(&e_aux->list);
	spin_unlock(&elv_list_lock);
	kfree(e_aux);
}

int elv_register(struct elevator_type *e)
{
	char *def = "";

	/* create icq_cache if requested */
	if (e->icq_size) {
		if (WARN_ON(e->icq_size < sizeof(struct io_cq)) ||
		    WARN_ON(e->icq_align < __alignof__(struct io_cq)))
			return -EINVAL;

		snprintf(e->icq_cache_name, sizeof(e->icq_cache_name),
			 "%s_io_cq", e->elevator_name);
		e->icq_cache = kmem_cache_create(e->icq_cache_name, e->icq_size,
						 e->icq_align, 0, NULL);
		if (!e->icq_cache)
			return -ENOMEM;
	}

	/*
	 * register, don't allow duplicate names, we never set e->ops
	 * for mq schedulers and always set it for non-mq schedulers,
	 * so this way is reliable to decide if it uses mq
	 */
	spin_lock(&elv_list_lock);
	if (elevator_find(e->elevator_name, !e->ops.elevator_init_fn)) {
		spin_unlock(&elv_list_lock);
		if (e->icq_cache)
			kmem_cache_destroy(e->icq_cache);
		return -EBUSY;
	}
	list_add_tail(&e->list, &elv_list);
	spin_unlock(&elv_list_lock);

	if (elv_aux_register(e))
		return -ENOMEM;

	/* print pretty message */
	if (elevator_match(e, chosen_elevator) ||
			(!*chosen_elevator &&
			 elevator_match(e, CONFIG_DEFAULT_IOSCHED)))
		def = " (default)";
	printk(KERN_INFO "io scheduler %s registered%s\n", e->elevator_name,
								def);
	return 0;
}
EXPORT_SYMBOL_GPL(elv_register);

void elv_unregister(struct elevator_type *e)
{
	/* unregister */
	spin_lock(&elv_list_lock);
	list_del_init(&e->list);
	spin_unlock(&elv_list_lock);

	/*
	 * Destroy icq_cache if it exists.  icq's are RCU managed.  Make
	 * sure all RCU operations are complete before proceeding.
	 */
	if (e->icq_cache) {
		rcu_barrier();
		kmem_cache_destroy(e->icq_cache);
		e->icq_cache = NULL;
	}
	elv_aux_unregister(e);
}
EXPORT_SYMBOL_GPL(elv_unregister);

static int elevator_switch_mq(struct request_queue *q,
			      struct elevator_type *new_e)
{
	int ret;

	blk_mq_freeze_queue(q);
	blk_mq_quiesce_queue(q);

	if (q->elevator) {
		if (q->elevator->registered)
			elv_unregister_queue(q);
		ioc_clear_queue(q);
		elevator_exit(q, q->elevator);
	}

	ret = blk_mq_init_sched(q, new_e);
	if (ret)
		goto out;

	if (new_e) {
		ret = elv_register_queue(q);
		if (ret) {
			elevator_exit(q, q->elevator);
			goto out;
		}
	}

	if (new_e)
		blk_add_trace_msg(q, "elv switch: %s", new_e->elevator_name);
	else
		blk_add_trace_msg(q, "elv switch: none");

out:
	blk_mq_unquiesce_queue(q);
	blk_mq_unfreeze_queue(q);
	return ret;
}

/*
 * switch to new_e io scheduler. be careful not to introduce deadlocks -
 * we don't free the old io scheduler, before we have allocated what we
 * need for the new one. this way we have a chance of going back to the old
 * one, if the new one fails init for some reason.
 */
static int elevator_switch(struct request_queue *q, struct elevator_type *new_e)
{
	struct elevator_queue *old = q->elevator;
	bool old_registered = false;
	int err;
	struct elevator_type_aux *aux;

	if (q->mq_ops)
		return elevator_switch_mq(q, new_e);

	/*
	 * Turn on BYPASS and drain all requests w/ elevator private data.
	 * Block layer doesn't call into a quiesced elevator - all requests
	 * are directly put on the dispatch list without elevator data
	 * using INSERT_BACK.  All requests have SOFTBARRIER set and no
	 * merge happens either.
	 */
	if (old) {
		old_registered = old->registered;

		blk_queue_bypass_start(q);

		/* unregister and clear all auxiliary data of the old elevator */
		if (old_registered)
			elv_unregister_queue(q);

		spin_lock_irq(q->queue_lock);
		ioc_clear_queue(q);
		spin_unlock_irq(q->queue_lock);
	}

	aux = elevator_aux_find(new_e);
	/* allocate, init and register new elevator */
	err = aux->ops.sq.elevator_init_fn(q, new_e);
	if (err)
		goto fail_init;

	err = elv_register_queue(q);
	if (err)
		goto fail_register;

	/* done, kill the old one and finish */
	if (old) {
		elevator_exit(q, old);
		blk_queue_bypass_end(q);
	}

	blk_add_trace_msg(q, "elv switch: %s", new_e->elevator_name);

	return 0;

fail_register:
	elevator_exit(q, q->elevator);
fail_init:
	/* switch failed, restore and re-register old elevator */
	if (old) {
		q->elevator = old;
		elv_register_queue(q);
		blk_queue_bypass_end(q);
	}

	return err;
}

/*
 * Switch this queue to the given IO scheduler.
 */
static int __elevator_change(struct request_queue *q, const char *name)
{
	char elevator_name[ELV_NAME_MAX];
	struct elevator_type *e;

	/* Make sure queue is not in the middle of being removed */
	if (!test_bit(QUEUE_FLAG_REGISTERED, &q->queue_flags))
		return -ENOENT;

	/*
	 * Special case for mq, turn off scheduling
	 */
	if (q->mq_ops && !strncmp(name, "none", 4))
		return elevator_switch(q, NULL);

	strlcpy(elevator_name, name, sizeof(elevator_name));
	e = elevator_get(q, strstrip(elevator_name), true);
	if (!e)
		return -EINVAL;

	if (q->elevator && elevator_match(q->elevator->type, elevator_name)) {
		elevator_put(e);
		return 0;
	}

	return elevator_switch(q, e);
}

int elevator_change(struct request_queue *q, const char *name)
{
	int ret;

	/* Protect q->elevator from elevator_init() */
	mutex_lock(&q->sysfs_lock);
	ret = __elevator_change(q, name);
	mutex_unlock(&q->sysfs_lock);

	return ret;
}
EXPORT_SYMBOL(elevator_change);

ssize_t elv_iosched_store(struct request_queue *q, const char *name,
			  size_t count)
{
	int ret;

	if (!(q->mq_ops || q->request_fn))
		return count;

	ret = __elevator_change(q, name);
	if (!ret)
		return count;

	return ret;
}

ssize_t elv_iosched_show(struct request_queue *q, char *name)
{
	struct elevator_queue *e = q->elevator;
	struct elevator_type *elv = NULL;
	struct elevator_type *__e;
	bool uses_mq = q->mq_ops != NULL;
	int len = 0;

	if (!blk_queue_stackable(q))
		return sprintf(name, "none\n");

	if (!q->elevator)
		len += sprintf(name+len, "[none] ");
	else
		elv = e->type;

	spin_lock(&elv_list_lock);
	list_for_each_entry(__e, &elv_list, list) {
		struct elevator_type_aux *aux;

		if (elv && __elevator_match(elv, __e->elevator_name) &&
		    (uses_mq == !__e->ops.elevator_init_fn)) {
			len += sprintf(name+len, "[%s] ", elv->elevator_name);
			continue;
		}

		aux = __elevator_aux_find(__e);
		if (aux->uses_mq && q->mq_ops)
			len += sprintf(name+len, "%s ", __e->elevator_name);
		else if (!aux->uses_mq && !q->mq_ops)
			len += sprintf(name+len, "%s ", __e->elevator_name);
	}
	spin_unlock(&elv_list_lock);

	if (q->mq_ops && q->elevator)
		len += sprintf(name+len, "none");

	len += sprintf(len+name, "\n");
	return len;
}

struct request *elv_rb_former_request(struct request_queue *q,
				      struct request *rq)
{
	struct rb_node *rbprev = rb_prev(&rq->rb_node);

	if (rbprev)
		return rb_entry_rq(rbprev);

	return NULL;
}
EXPORT_SYMBOL(elv_rb_former_request);

struct request *elv_rb_latter_request(struct request_queue *q,
				      struct request *rq)
{
	struct rb_node *rbnext = rb_next(&rq->rb_node);

	if (rbnext)
		return rb_entry_rq(rbnext);

	return NULL;
}
EXPORT_SYMBOL(elv_rb_latter_request);
