/*
 * blk-mq scheduling framework
 *
 * Copyright (C) 2016 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/blk-mq.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"

void blk_mq_sched_free_hctx_data(struct request_queue *q,
				 void (*exit)(struct blk_mq_hw_ctx *))
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (exit && hctx->sched_data)
			exit(hctx);
		kfree(hctx->sched_data);
		hctx->sched_data = NULL;
	}
}
EXPORT_SYMBOL_GPL(blk_mq_sched_free_hctx_data);

static void __blk_mq_sched_assign_ioc(struct request_queue *q,
				      struct request *rq,
				      struct bio *bio,
				      struct io_context *ioc)
{
	struct io_cq *icq;

	spin_lock_irq(q->queue_lock);
	icq = ioc_lookup_icq(ioc, q);
	spin_unlock_irq(q->queue_lock);

	if (!icq) {
		icq = ioc_create_icq(ioc, q, GFP_ATOMIC);
		if (!icq)
			return;
	}

	rq->elv.icq = icq;
	if (!blk_mq_sched_get_rq_priv(q, rq, bio)) {
		rq->cmd_flags |= REQ_ELVPRIV;
		get_io_context(icq->ioc);
		return;
	}

	rq->elv.icq = NULL;
}

static void blk_mq_sched_assign_ioc(struct request_queue *q,
				    struct request *rq, struct bio *bio)
{
	struct io_context *ioc;

	ioc = rq_ioc(bio);
	if (ioc)
		__blk_mq_sched_assign_ioc(q, rq, bio, ioc);
}

/*
 * Mark a hardware queue as needing a restart. For shared queues, maintain
 * a count of how many hardware queues are marked for restart.
 */
static void blk_mq_sched_mark_restart_hctx(struct blk_mq_hw_ctx *hctx)
{
	if (test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
		return;

	if (hctx->flags & BLK_MQ_F_TAG_SHARED) {
		struct request_queue *q = hctx->queue;

		if (!test_and_set_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
			atomic_inc(&q->shared_hctx_restart);
	} else
		set_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);
}

static bool blk_mq_sched_restart_hctx(struct blk_mq_hw_ctx *hctx)
{
	if (!test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
		return false;

	if (hctx->flags & BLK_MQ_F_TAG_SHARED) {
		struct request_queue *q = hctx->queue;

		if (test_and_clear_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
			atomic_dec(&q->shared_hctx_restart);
	} else
		clear_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);

	return blk_mq_run_hw_queue(hctx, true);
}

struct request *blk_mq_sched_get_request(struct request_queue *q,
					 struct bio *bio,
					 unsigned int op,
					 struct blk_mq_alloc_data *data)
{
	struct elevator_queue *e = q->elevator;
	struct request *rq;
	const bool is_flush = op & (REQ_FLUSH | REQ_FUA);

	blk_queue_enter_live(q);
	data->q = q;
    
	if (likely(!data->ctx))
		data->ctx = blk_mq_get_ctx(q);
	if (likely(!data->hctx))
		data->hctx = blk_mq_map_queue(q, data->ctx->cpu);

	if (e) {//有调度器
		data->flags |= BLK_MQ_REQ_INTERNAL;//有调度时，设置BLK_MQ_REQ_INTERNAL标志

		/*
		 * Flush requests are special and go directly to the
		 * dispatch list.
		 */
		if (!is_flush && e->aux->ops.mq.get_request) {
			rq = e->aux->ops.mq.get_request(q, op, data);
			if (rq)
				rq->cmd_flags |= REQ_QUEUED;
		} else
			rq = __blk_mq_alloc_request(data, op);
	} else {
		rq = __blk_mq_alloc_request(data, op);
	}

	if (rq) {
		if (!is_flush) {
			rq->elv.icq = NULL;
			if (e && e->type->icq_cache)
				blk_mq_sched_assign_ioc(q, rq, bio);
		}
		data->hctx->queued++;
		return rq;
	}

	blk_queue_exit(q);
	return NULL;
}

void blk_mq_sched_put_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (rq->cmd_flags & REQ_ELVPRIV) {
		blk_mq_sched_put_rq_priv(rq->q, rq);
		if (rq->elv.icq) {
			put_io_context(rq->elv.icq->ioc);
			rq->elv.icq = NULL;
		}
	}

	if ((rq->cmd_flags & REQ_QUEUED) && e && e->aux->ops.mq.put_request)
		e->aux->ops.mq.put_request(rq);
	else
		blk_mq_finish_request(rq);
}

/*
 * Only SCSI implements .get_budget and .put_budget, and SCSI restarts
 * its queue by itself in its completion handler, so we don't need to
 * restart queue if .get_budget() returns BLK_STS_NO_RESOURCE.
 */
static void blk_mq_do_dispatch_sched(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct elevator_queue *e = q->elevator;
	LIST_HEAD(rq_list);

	do {
		struct request *rq;

		if (e->aux->ops.mq.has_work &&
				!e->aux->ops.mq.has_work(hctx))
			break;

		if (!blk_mq_get_dispatch_budget(hctx))
			break;

		rq = e->aux->ops.mq.dispatch_request(hctx);
		if (!rq) {
			blk_mq_put_dispatch_budget(hctx);
			break;
		}

		/*
		 * Now this rq owns the budget which has to be released
		 * if this rq won't be queued to driver via .queue_rq()
		 * in blk_mq_dispatch_rq_list().
		 */
		list_add(&rq->queuelist, &rq_list);
	} while (blk_mq_dispatch_rq_list(q, &rq_list, true));
}

static struct blk_mq_ctx *blk_mq_next_ctx(struct blk_mq_hw_ctx *hctx,
					  struct blk_mq_ctx *ctx)
{
	unsigned idx = ctx->index_hw;

	if (++idx == hctx->nr_ctx)
		idx = 0;

	return hctx->ctxs[idx];
}

/*
 * Only SCSI implements .get_budget and .put_budget, and SCSI restarts
 * its queue by itself in its completion handler, so we don't need to
 * restart queue if .get_budget() returns BLK_STS_NO_RESOURCE.
 */
static void blk_mq_do_dispatch_ctx(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	LIST_HEAD(rq_list);
	struct blk_mq_ctx *ctx = READ_ONCE(hctx->dispatch_from);

	do {
		struct request *rq;

		if (!sbitmap_any_bit_set(&hctx->ctx_map))
			break;

		if (!blk_mq_get_dispatch_budget(hctx))
			break;

		rq = blk_mq_dequeue_from_ctx(hctx, ctx);
		if (!rq) {
			blk_mq_put_dispatch_budget(hctx);
			break;
		}

		/*
		 * Now this rq owns the budget which has to be released
		 * if this rq won't be queued to driver via .queue_rq()
		 * in blk_mq_dispatch_rq_list().
		 */
		list_add(&rq->queuelist, &rq_list);

		/* round robin for fair dispatch */
		ctx = blk_mq_next_ctx(hctx, rq->mq_ctx);

	} while (blk_mq_dispatch_rq_list(q, &rq_list, true));

	WRITE_ONCE(hctx->dispatch_from, ctx);
}

/* return true if hw queue need to be run again */
void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct elevator_queue *e = q->elevator;
	const bool has_sched_dispatch = e && e->aux->ops.mq.dispatch_request;
	LIST_HEAD(rq_list);

	/* RCU or SRCU read lock is needed before checking quiesced flag */
	if (unlikely(blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)))
		return;

	hctx->run++;

	/*
	 * If we have previous entries on our dispatch list, grab them first for
	 * more fair dispatch.
	 */
	if (!list_empty_careful(&hctx->dispatch)) {
		spin_lock(&hctx->lock);
		if (!list_empty(&hctx->dispatch))
			list_splice_init(&hctx->dispatch, &rq_list);
		spin_unlock(&hctx->lock);
	}

	/*
	 * Only ask the scheduler for requests, if we didn't have residual
	 * requests from the dispatch list. This is to avoid the case where
	 * we only ever dispatch a fraction of the requests available because
	 * of low device queue depth. Once we pull requests out of the IO
	 * scheduler, we can no longer merge or sort them. So it's best to
	 * leave them there for as long as we can. Mark the hw queue as
	 * needing a restart in that case.
	 *
	 * We want to dispatch from the scheduler if there was nothing
	 * on the dispatch list or we were able to dispatch from the
	 * dispatch list.
	 */
	if (!list_empty(&rq_list)) {
		blk_mq_sched_mark_restart_hctx(hctx);
		if (blk_mq_dispatch_rq_list(q, &rq_list, false)) {
			if (has_sched_dispatch)
				blk_mq_do_dispatch_sched(hctx);
			else
				blk_mq_do_dispatch_ctx(hctx);
		}
	} else if (has_sched_dispatch) {
		blk_mq_do_dispatch_sched(hctx);
	} else if (hctx->dispatch_busy) {
		/* dequeue request one by one from sw queue if queue is busy */
		blk_mq_do_dispatch_ctx(hctx);
	} else {
		blk_mq_flush_busy_ctxs(hctx, &rq_list);
		blk_mq_dispatch_rq_list(q, &rq_list, false);
	}
}

void blk_mq_sched_move_to_dispatch(struct blk_mq_hw_ctx *hctx,
				   struct list_head *rq_list,
				   struct request *(*get_rq)(struct blk_mq_hw_ctx *))
{
	do {
		struct request *rq;

		rq = get_rq(hctx);
		if (!rq)
			break;

		list_add_tail(&rq->queuelist, rq_list);
	} while (1);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_move_to_dispatch);

//在IO调度器队列里查找是否有可以合并的req，找到则可以bio后项或前项合并到req，还会触发二次合并，还会对合并后的req在IO调度算法队列里重新排序
bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
			    struct request **merged_request)
{
	struct request *rq;
	int ret;

//在elv调度器队列里查找是否有可以合并的req，找到则可以bio后项或前项合并到req。这个是调用具体的IO调度算法函数寻找可以合并的req。
//函数返回值 ELEVATOR_BACK_MERGE(前项合并的req)、ELEVATOR_FRONT_MERGE(前项合并)、ELEVATOR_NO_MERGE(没有找到可以合并的req)
	ret = elv_merge(q, &rq, bio);
	if (ret == ELEVATOR_BACK_MERGE) {//后项合并
		if (!blk_mq_sched_allow_merge(q, rq, bio))
			return false;
        //req和bio二者磁盘范围挨着，req向后合并本次的bio，合并成功返回真
		if (bio_attempt_back_merge(q, rq, bio)) {
            //二次合并，即req和bio合并后，新的req代表的磁盘结束地址又与其他req磁盘起始地址挨着了，那就接着后项合并
			*merged_request = attempt_back_merge(q, rq);
			if (!*merged_request)//如果没有发生二次合并，则对req对在deadline调度算法红黑树队列中重新排序
				elv_merged_request(q, rq, ret);
			return true;
		}
	} else if (ret == ELEVATOR_FRONT_MERGE) {//前项合并
		if (!blk_mq_sched_allow_merge(q, rq, bio))
			return false;
        //req和bio二者磁盘范围挨着，req向前合并本次的bio，合并成功返回真
		if (bio_attempt_front_merge(q, rq, bio)) {
            //二次合并，即req和bio合并后，新的req代表的磁盘空间起始地址又与其他req挨着了，那就接着前项合并
			*merged_request = attempt_front_merge(q, rq);
			if (!*merged_request)//如果没有发生二次合并，则对req对在deadline hash队列中重新排序
				elv_merged_request(q, rq, ret);
			return true;
		}
	}

	return false;
}
EXPORT_SYMBOL_GPL(blk_mq_sched_try_merge);

bool __blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (e->aux->ops.mq.bio_merge) {
        //从q->queue_ctx得到每个CPU专属的软件队列
		struct blk_mq_ctx *ctx = blk_mq_get_ctx(q);
        //根据软件队列ctx->cpu绑定的CPU编号，去q->queue_hw_ctx[]寻找硬件队列
		struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);

		blk_mq_put_ctx(ctx);
//在IO调度器队列里查找是否有可以合并的req，找到则可以bio后项或前项合并到req，还会触发二次合并，还会对合并后的req在IO调度算法队列里重新排序
//这个合并跟软件队列和硬件队列没有半毛钱的关系吧
		return e->aux->ops.mq.bio_merge(hctx, bio);//mq-deadline调度算法dd_bio_merge
	}

	return false;
}

bool blk_mq_sched_try_insert_merge(struct request_queue *q, struct request *rq)
{
	return rq_mergeable(rq) && elv_attempt_insert_merge(q, rq);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_try_insert_merge);

void blk_mq_sched_request_inserted(struct request *rq)
{
	trace_block_rq_insert(rq->q, rq);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_request_inserted);

static bool blk_mq_sched_bypass_insert(struct blk_mq_hw_ctx *hctx,
				       bool has_sched,
				       struct request *rq)
{
	/* dispatch flush rq directly */
	if (rq->cmd_flags & REQ_FLUSH_SEQ) {
		spin_lock(&hctx->lock);
		list_add(&rq->queuelist, &hctx->dispatch);
		spin_unlock(&hctx->lock);
		return true;
	}

	if (has_sched)
		rq->cmd_flags |= REQ_SORTED;

	return false;
}

/**
 * list_for_each_entry_rcu_rr - iterate in a round-robin fashion over rcu list
 * @pos:    loop cursor.
 * @skip:   the list element that will not be examined. Iteration starts at
 *          @skip->next.
 * @head:   head of the list to examine. This list must have at least one
 *          element, namely @skip.
 * @member: name of the list_head structure within typeof(*pos).
 */
#define list_for_each_entry_rcu_rr(pos, skip, head, member)		\
	for ((pos) = (skip);						\
	     (pos = (pos)->member.next != (head) ? list_entry_rcu(	\
			(pos)->member.next, typeof(*pos), member) :	\
	      list_entry_rcu((pos)->member.next->next, typeof(*pos), member)), \
	     (pos) != (skip); )

/*
 * Called after a driver tag has been freed to check whether a hctx needs to
 * be restarted. Restarts @hctx if its tag set is not shared. Restarts hardware
 * queues in a round-robin fashion if the tag set of @hctx is shared with other
 * hardware queues.
 */
void blk_mq_sched_restart(struct blk_mq_hw_ctx *const hctx)
{
	struct blk_mq_tags *const tags = hctx->tags;
	struct blk_mq_tag_set *const set = hctx->queue->tag_set;
	struct request_queue *const queue = hctx->queue, *q;
	struct blk_mq_hw_ctx *hctx2;
	unsigned int i, j;

	if (set->flags & BLK_MQ_F_TAG_SHARED) {
		/*
		 * If this is 0, then we know that no hardware queues
		 * have RESTART marked. We're done.
		 */
		if (!atomic_read(&queue->shared_hctx_restart))
			return;

		rcu_read_lock();
		list_for_each_entry_rcu_rr(q, queue, &set->tag_list,
					   tag_set_list) {
			queue_for_each_hw_ctx(q, hctx2, i)
				if (hctx2->tags == tags &&
				    blk_mq_sched_restart_hctx(hctx2))
					goto done;
		}
		j = hctx->queue_num + 1;
		for (i = 0; i < queue->nr_hw_queues; i++, j++) {
			if (j == queue->nr_hw_queues)
				j = 0;
			hctx2 = queue->queue_hw_ctx[j];
			if (hctx2->tags == tags &&
			    blk_mq_sched_restart_hctx(hctx2))
				break;
		}
done:
		rcu_read_unlock();
	} else {
		blk_mq_sched_restart_hctx(hctx);
	}
}

void blk_mq_sched_insert_request(struct request *rq, bool at_head,
				 bool run_queue, bool async)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);

	/* flush rq in flush machinery need to be dispatched directly */
	if (!(rq->cmd_flags & REQ_FLUSH_SEQ) && (rq->cmd_flags & (REQ_FLUSH | REQ_FUA))) {
		blk_insert_flush(rq);
		goto run;
	}

	WARN_ON(e && (rq->tag != -1));

	if (blk_mq_sched_bypass_insert(hctx, !!e, rq))
		goto run;

	if (e && e->aux->ops.mq.insert_requests) {
		LIST_HEAD(list);

		list_add(&rq->queuelist, &list);
		e->aux->ops.mq.insert_requests(hctx, &list, at_head);
	} else {
		spin_lock(&ctx->lock);
		__blk_mq_insert_request(hctx, rq, at_head);
		spin_unlock(&ctx->lock);
	}

run:
	if (run_queue)
		blk_mq_run_hw_queue(hctx, async);
}

void blk_mq_sched_insert_requests(struct request_queue *q,
				  struct blk_mq_ctx *ctx,
				  struct list_head *list, bool run_queue_async)
{
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);
	struct elevator_queue *e = hctx->queue->elevator;

	if (e && e->aux->ops.mq.insert_requests)
		e->aux->ops.mq.insert_requests(hctx, list, false);
	else {
		/*
		 * try to issue requests directly if the hw queue isn't
		 * busy in case of 'none' scheduler, and this way may save
		 * us one extra enqueue & dequeue to sw queue.
		 */
		if (!hctx->dispatch_busy && !e && !run_queue_async) {
			blk_mq_try_issue_list_directly(hctx, list);
			if (list_empty(list))
				return;
		}
		blk_mq_insert_requests(hctx, ctx, list);
	}

	blk_mq_run_hw_queue(hctx, run_queue_async);
}

static void blk_mq_sched_free_tags(struct blk_mq_tag_set *set,
				   struct blk_mq_hw_ctx *hctx,
				   unsigned int hctx_idx)
{
	if (hctx->sched_tags) {
		blk_mq_free_rqs(set, hctx->sched_tags, hctx_idx);
		blk_mq_free_rq_map(hctx->sched_tags);
		hctx->sched_tags = NULL;
	}
}
//为硬件队列结构hctx->sched_tags分配blk_mq_tags，一个硬件队列一个blk_mq_tags，然后根据为这个blk_mq_tags分配q->nr_requests个request，存于tags->static_rqs[]
static int blk_mq_sched_alloc_tags(struct request_queue *q,
				   struct blk_mq_hw_ctx *hctx,
				   unsigned int hctx_idx)
{
	struct blk_mq_tag_set *set = q->tag_set;
	int ret;
    //分配blk_mq_tags结构，分配设置其成员nr_reserved_tags、nr_tags、rqs、static_rqs
	hctx->sched_tags = blk_mq_alloc_rq_map(set, hctx_idx, q->nr_requests,
					       set->reserved_tags);
	if (!hctx->sched_tags)
		return -ENOMEM;

//针对hctx_idx编号的硬件队列，每一层队列深度都分配request(共分配q->nr_requests个request)赋值于tags->static_rqs[]。具体是分配N个page，将page的内存一片片分割成request集合大小
//然后tags->static_rqs记录每一个request首地址，然后执行nvme_init_request()底层驱动初始化函数,建立request与nvme队列的关系吧
	ret = blk_mq_alloc_rqs(set, hctx->sched_tags, hctx_idx, q->nr_requests);
	if (ret)
		blk_mq_sched_free_tags(set, hctx, hctx_idx);

	return ret;
}

static void blk_mq_sched_tags_teardown(struct request_queue *q)
{
	struct blk_mq_tag_set *set = q->tag_set;
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_sched_free_tags(set, hctx, i);
}

int blk_mq_sched_init_hctx(struct request_queue *q, struct blk_mq_hw_ctx *hctx,
			   unsigned int hctx_idx)
{
	struct elevator_queue *e = q->elevator;
	int ret;

	if (!e)
		return 0;
    //为硬件队列结构hctx->sched_tags分配blk_mq_tags，一个硬件队列一个blk_mq_tags，然后根据为这个blk_mq_tags分配q->nr_requests个request，存于tags->static_rqs[]
	ret = blk_mq_sched_alloc_tags(q, hctx, hctx_idx);
	if (ret)
		return ret;

	if (e->aux->ops.mq.init_hctx) {
		ret = e->aux->ops.mq.init_hctx(hctx, hctx_idx);//nvme_init_hctx
		if (ret) {
			blk_mq_sched_free_tags(q->tag_set, hctx, hctx_idx);
			return ret;
		}
	}

	blk_mq_debugfs_register_sched_hctx(q, hctx);

	return 0;
}

void blk_mq_sched_exit_hctx(struct request_queue *q, struct blk_mq_hw_ctx *hctx,
			    unsigned int hctx_idx)
{
	struct elevator_queue *e = q->elevator;

	if (!e)
		return;

	blk_mq_debugfs_unregister_sched_hctx(hctx);

	if (e->aux->ops.mq.exit_hctx && hctx->sched_data) {
		e->aux->ops.mq.exit_hctx(hctx, hctx_idx);
		hctx->sched_data = NULL;
	}

	blk_mq_sched_free_tags(q->tag_set, hctx, hctx_idx);
}

int blk_mq_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct blk_mq_hw_ctx *hctx;
	struct elevator_queue *eq;
	unsigned int i;
	int ret;
	struct elevator_type_aux *aux;

	if (!e) {
		q->elevator = NULL;
		q->nr_requests = q->tag_set->queue_depth;
		return 0;
	}

	/*
	 * Default to double of smaller one between hw queue_depth and 128,
	 * since we don't split into sync/async like the old code did.
	 * Additionally, this is a per-hw queue depth.
	 */
	q->nr_requests = 2 * min_t(unsigned int, q->tag_set->queue_depth,
				   BLKDEV_MAX_RQ);

	queue_for_each_hw_ctx(q, hctx, i) {
		ret = blk_mq_sched_alloc_tags(q, hctx, i);
		if (ret)
			goto err;
	}

	aux = elevator_aux_find(e);
	ret = aux->ops.mq.init_sched(q, e);
	if (ret)
		goto err;

	blk_mq_debugfs_register_sched(q);

	queue_for_each_hw_ctx(q, hctx, i) {
		if (aux->ops.mq.init_hctx) {
			ret = aux->ops.mq.init_hctx(hctx, i);
			if (ret) {
				eq = q->elevator;
				blk_mq_exit_sched(q, eq);
				kobject_put(&eq->kobj);
				return ret;
			}
		}
		blk_mq_debugfs_register_sched_hctx(q, hctx);
	}

	return 0;

err:
	blk_mq_sched_tags_teardown(q);
	q->elevator = NULL;
	return ret;
}

void blk_mq_exit_sched(struct request_queue *q, struct elevator_queue *e)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		blk_mq_debugfs_unregister_sched_hctx(hctx);
		if (e->aux->ops.mq.exit_hctx && hctx->sched_data) {
			e->aux->ops.mq.exit_hctx(hctx, i);
			hctx->sched_data = NULL;
		}
	}
	blk_mq_debugfs_unregister_sched(q);
	if (e->aux->ops.mq.exit_sched)
		e->aux->ops.mq.exit_sched(e);
	blk_mq_sched_tags_teardown(q);
	q->elevator = NULL;
}

int blk_mq_sched_init(struct request_queue *q)
{
	int ret;

	mutex_lock(&q->sysfs_lock);
	ret = elevator_init(q, NULL);
	mutex_unlock(&q->sysfs_lock);

	return ret;
}
