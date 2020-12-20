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
//标记hctx->state的BLK_MQ_S_SCHED_RESTART标志位
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
/*从硬件队列的blk_mq_tags结构体的tags->bitmap_tags或者tags->nr_reserved_tags分配一个空闲tag，然后req = tags->static_rqs[tag]
从static_rqs[]分配一个req，再req->tag=tag。接着hctx->tags->rqs[rq->tag] = rq，一个req必须分配一个tag才能IO传输。
分配失败则启动硬件IO数据派发，之后再尝试分配tag*/
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
		data->ctx = blk_mq_get_ctx(q);//data->ctx 获取当前进程所属CPU的专有软件队列
	if (likely(!data->hctx))
		data->hctx = blk_mq_map_queue(q, data->ctx->cpu);//获取软件队列的硬件队列，CPU、软件队列、硬件队列是一一对应关系

	if (e) {//使用调度器
		data->flags |= BLK_MQ_REQ_INTERNAL;//使用调度时，设置BLK_MQ_REQ_INTERNAL标志

		/*
		 * Flush requests are special and go directly to the
		 * dispatch list.
		 */
		if (!is_flush && e->aux->ops.mq.get_request) {
			rq = e->aux->ops.mq.get_request(q, op, data);
			if (rq)
				rq->cmd_flags |= REQ_QUEUED;
		} else
		/*从硬件队列的blk_mq_tags结构体的tags->bitmap_tags或者tags->nr_reserved_tags分配一个空闲tag，然后req = tags->static_rqs[tag]
        从static_rqs[]分配一个req，再req->tag=tag。接着hctx->tags->rqs[rq->tag] = rq，一个req必须分配一个tag才能IO传输。
        分配失败则启动硬件IO数据派发，之后再尝试分配tag*/
			rq = __blk_mq_alloc_request(data, op);
	} else {//无调度器
	
        //同理
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
//执行deadline算法派发函数，循环从fifo或者红黑树队列选择待派发给传输的req，然后给req在硬件队列hctx的blk_mq_tags里分配一个空闲tag，
//然后把req派发给块设备驱动。如果磁盘驱动硬件繁忙，则把req转移到hctx->dispatch队列，然后启动req异步传输。
//硬件队列繁忙或者deadline算法队列没有req了则跳出循环。
static void blk_mq_do_dispatch_sched(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct elevator_queue *e = q->elevator;
	LIST_HEAD(rq_list);

	do {
		struct request *rq;

		if (e->aux->ops.mq.has_work &&
				!e->aux->ops.mq.has_work(hctx))//dd_has_work，判断有req要传输吧，无则break
			break;

		if (!blk_mq_get_dispatch_budget(hctx))
			break;

 //执行deadline算法派发函数，从fifo或者红黑树队列选择待派发的req返回。然后设置新的next_rq，并把req从fifo队列和红黑树队列剔除，
 //req来源有:上次派发设置的next_rq;read req派发过多而选择的write req;fifo 队列上超时要传输的req，统筹兼顾，有固定策略
		rq = e->aux->ops.mq.dispatch_request(hctx);//dd_dispatch_request
		if (!rq) {
			blk_mq_put_dispatch_budget(hctx);
			break;
		}

		/*
		 * Now this rq owns the budget which has to be released
		 * if this rq won't be queued to driver via .queue_rq()
		 * in blk_mq_dispatch_rq_list().
		 */
		//把选择出来派发的req加入局部变量rq_list链表
		list_add(&rq->queuelist, &rq_list);

//blk_mq_dispatch_rq_list作用:遍历rq_list上的req，先给req在硬件队列hctx的blk_mq_tags里分配一个空闲tag，就是
//建立req与硬件队列的联系吧，然后直接启动nvme硬件传输。看着任一个req要启动硬件传输，都要从blk_mq_tags结构里得到一个空闲的tag。
//如果nvme硬件队列繁忙，还要把rq_list剩余的req转移到hctx->dispatch队列，然后启动nvme异步传输。硬件队列繁忙返回flase!!!!!!

//这个设计我觉得有问题，rq_list链表有啥用?每次dd_dispatch_request从算法队列里取出一个待派发的req，放到rq_list，接着就执行
//blk_mq_dispatch_rq_list启动req传输，rq_list只有一个req呀，为什么不多积攒几个req到rq_list再执行blk_mq_dispatch_rq_list呢??????????
	}while (blk_mq_dispatch_rq_list(q, &rq_list, true));//硬件队列繁忙或者rq_list链表空则返回flase，跳出循环
    
}

static struct blk_mq_ctx *blk_mq_next_ctx(struct blk_mq_hw_ctx *hctx,
					  struct blk_mq_ctx *ctx)
{
    //硬件队列hctx关联的第ctx->index_hw个软件队列是ctx
	unsigned idx = ctx->index_hw;

    //显然达到硬件队列关联的最大软件队列数，则从关联的0号软件队列开始
	if (++idx == hctx->nr_ctx)
		idx = 0;
    //返回硬件队列关联的第idx的软件队列
	return hctx->ctxs[idx];
}

/*
 * Only SCSI implements .get_budget and .put_budget, and SCSI restarts
 * its queue by itself in its completion handler, so we don't need to
 * restart queue if .get_budget() returns BLK_STS_NO_RESOURCE.
 */
//依次循环遍历hctx硬件队列关联的所有软件队列，依次取出一个软件队列ctx->rq_list上的req加入rq_list局部链表，执行blk_mq_dispatch_rq_list()硬件派发req。
//如果nvme硬件队列繁忙，还要把rq_list剩余的req转移到hctx->dispatch队列，然后启动nvme异步传输。循环退出条件是，nvme硬件队列繁忙
//或者hctx硬件队列关联的所有软件队列上的req全都派发完。有个疑问，如果是nvme硬件队列繁忙，那有可能有些软件队列上的req还没来得及派发呀?????????????
static void blk_mq_do_dispatch_ctx(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	LIST_HEAD(rq_list);
	struct blk_mq_ctx *ctx = READ_ONCE(hctx->dispatch_from);

    //依次遍历hctx硬件队列关联的所有软件队列
	do {
		struct request *rq;

        //这应该是检测硬件队列关联的软件队列有没有待传输的req吧???????
		if (!sbitmap_any_bit_set(&hctx->ctx_map))
			break;

		if (!blk_mq_get_dispatch_budget(hctx))
			break;
        
        //从软件队列ctx->rq_list链表取出req，然后从软件队列中剔除req。接着清除hctx->ctx_map中软件队列对应的标志位???????
		rq = blk_mq_dequeue_from_ctx(hctx, ctx);
		if (!rq) {
			blk_mq_put_dispatch_budget(hctx);
			break;
		}
    /*这个软件队列上的req的派发，我看着更迷，一次只从软件队列取出一个req，然后给送blk_mq_dispatch_rq_list硬件派发，
      然后就取出硬件队列关联的下一个软件队列，再取出这个软件队列上的req派发??????为什么要这样折腾呀，把一个软件队列上
      的req全部派发完，再处理下一个软件队列上的req不行吗?循环处理直到所有ctx软件上的所有req都处理完退出循环，硬件队列忙也会退出。
      我还是觉得有点扯淡，一次处理一个软件队列上的一个req，然后就切换到下一个软件队列，循环，这样做的意义是什么呢?虽说这样也会
      遍历完软件队列上的req??????不对呀，如果nvme硬件队列繁忙，blk_mq_dispatch_rq_list返回false，就退出循环了，这样有可能有的
      软件队列上上的req没有来得及处理呀，就跳出这个循环了?????????????针对这种情况，到底是怎么处理的???????????
    */

		/*
		 * Now this rq owns the budget which has to be released
		 * if this rq won't be queued to driver via .queue_rq()
		 * in blk_mq_dispatch_rq_list().
		 */
		//req加入到rq_list
		list_add(&rq->queuelist, &rq_list);

		/* round robin for fair dispatch */
        //取出硬件队列关联的下一个软件队列
		ctx = blk_mq_next_ctx(hctx, rq->mq_ctx);

    //遍历rq_list上的req，先给req在硬件队列hctx的blk_mq_tags里分配一个空闲tag，就是
    //建立req与硬件队列的联系吧，然后直接启动nvme硬件传输。看着任一个req要启动硬件传输，都要从blk_mq_tags结构里得到一个空闲的tag。
    //如果nvme硬件队列繁忙，还要把rq_list剩余的req转移到hctx->dispatch队列，然后启动nvme异步传输
	} while (blk_mq_dispatch_rq_list(q, &rq_list, true));//硬件队列繁忙或者rq_list链表空则返回flase，跳出循环

    //赋值hctx->dispatch_from = ctx
	WRITE_ONCE(hctx->dispatch_from, ctx);
}

/* return true if hw queue need to be run again */
//各种各样场景的req派发，hctx->dispatch硬件队列dispatch链表上的req派发;有deadline调度算法时红黑树或者fifo调度队列上的req派发，
//无IO调度算法时，硬件队列关联的所有软件队列ctx->rq_list上的req的派发等等。派发过程应该都是调用blk_mq_dispatch_rq_list()，
//nvme硬件队列不忙直接启动req传输，繁忙的话则把剩余的req转移到hctx->dispatch队列，然后启动nvme异步传输
void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct elevator_queue *e = q->elevator;
	const bool has_sched_dispatch = e && e->aux->ops.mq.dispatch_request;//有IO调度器是__dd_dispatch_request
	LIST_HEAD(rq_list);

	/* RCU or SRCU read lock is needed before checking quiesced flag */
	if (unlikely(blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)))
		return;

	hctx->run++;

	/*
	 * If we have previous entries on our dispatch list, grab them first for
	 * more fair dispatch.
	 */
	//如果hctx->dispatch上有req要派发，
	if (!list_empty_careful(&hctx->dispatch)) {
		spin_lock(&hctx->lock);
        //把hctx->dispatch链表上的req转移到局部rq_list
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
	 
	//如果hctx->dispatch上有req要派发，hctx->dispatch链表上的req已经转移到rq_list
	if (!list_empty(&rq_list)) {
        
        //这里设置了hctx->state的BLK_MQ_S_SCHED_RESTART标志位
		blk_mq_sched_mark_restart_hctx(hctx);

        //rq_list上的req来自hctx->dispatch硬件派发队列，遍历list上的req，先给req在硬件队列hctx的blk_mq_tags里分配一个空闲tag，
        //就是建立req与硬件队列的联系吧，然后把req派发给块设备驱动。看着任一个req要启动硬件传输，都要从blk_mq_tags结构里得到一个空闲
        //的tag。如果nvme硬件队列繁忙，还要把list剩余的req转移到hctx->dispatch，启动异步传输。下发给块设备驱动的req成功减失败总个数不为0返回true
		if (blk_mq_dispatch_rq_list(q, &rq_list, false)) {

            //走到这里，说明blk_mq_dispatch_rq_list()中把hctx->dispatch队列上下发给块设备驱动的req成功减失败总个数不为，总之
            //hctx->dispatch队列上的req有成功下发给块设备驱动
            
			if (has_sched_dispatch)//有调度器则接着派发调度器队列上的req
			
                //执行deadline算法派发函数，循环从fifo或者红黑树队列选择待派发给传输的req，然后给req在硬件队列hctx的blk_mq_tags里分配
                //一个空闲tag，就是建立req与硬件队列的联系吧。然后把req派发给块设备驱动。如果nvme硬件队列繁忙，则把req转移到
                //hctx->dispatch队列，然后启动nvme异步传输。硬件队列繁忙或者deadline算法队列没有req了则跳出循环。
				blk_mq_do_dispatch_sched(hctx);
            
			else//无调度器派发软件队列上的req
                //依次循环遍历hctx硬件队列关联的所有软件队列，依次取出一个软件队列ctx->rq_list上的req加入rq_list局部链表，执行
                //blk_mq_dispatch_rq_list()硬件派发req。如果nvme硬件队列繁忙，还要把rq_list剩余的req转移到hctx->dispatch队列，然后
                //启动nvme异步传输。循环退出条件是，nvme硬件队列繁忙或者hctx硬件队列关联的所有软件队列上的req全都派发完。
                /*有个疑问，如果是nvme硬件队列繁忙，那有可能有些软件队列上的req还没来得及派发呀????????????????*/
				blk_mq_do_dispatch_ctx(hctx);
		}
	}
    else if (has_sched_dispatch) {//如果hctx->dispatch上没有req要派发,但是有调度器，并且调度器有注册了dispatch_request函数
         //与上边一样，执行blk_mq_do_dispatch_sched(),执行deadline算法派发函数，循环从fifo或者红黑树队列选择待派发给传输的req去派发
		blk_mq_do_dispatch_sched(hctx);
    
	} else if (hctx->dispatch_busy) {//如果hctx->dispatch链表上没有req派发，并且硬件队列繁忙
		/* dequeue request one by one from sw queue if queue is busy */
        //与上边一样，依次循环遍历hctx硬件队列关联的所有软件队列，取出一个软件队列上的req去派发
		blk_mq_do_dispatch_ctx(hctx);
	} else {
	    //把硬件队列hctx关联的软件队列上的ctx->rq_list链表上req转移到传入的rq_list链表尾部，然后清空ctx->rq_list链表。
        //这样貌似是把硬件队列hctx关联的所有软件队列ctx->rq_list链表上的req全部移动到局部rq_list链表尾部呀
		blk_mq_flush_busy_ctxs(hctx, &rq_list);
        //遍历rq_list上的req，先给req在硬件队列hctx的blk_mq_tags里分配一个空闲tag，就是
        //建立req与硬件队列的联系吧，然后将req派发给块设备驱动。看着任一个req要启动硬件传输，都要从blk_mq_tags结构里得到一个空闲的tag。
        //如果nvme硬件队列繁忙，还要把rq_list剩余的req转移到hctx->dispatch队列，然后启动nvme异步传输
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
//首先尝试将rq后项合并到q->last_merge，再尝试将rq后项合并到hash队列的某一个__rq，合并规则是rq的扇区起始地址等于q->last_merge或__rq
//的扇区结束地址，都是调用blk_attempt_req_merge()进行合并。并更新IO使用率等数据。如果使用了deadline调度算法，更新合并后的req在
//hash队列中的位置。还会从fifo队列剔除掉rq，更新dd->next_rq[]赋值rq的下一个req。
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
				 bool run_queue, bool async)//blk_mq_make_request()中调用该函数将req插入IO调度队列时，run_queue和async都是true
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

	if (e && e->aux->ops.mq.insert_requests) {//使用调度器并且定义了insert_requests函数，mq-deadline算法时dd_insert_requests()
		LIST_HEAD(list);

		list_add(&rq->queuelist, &list);
		e->aux->ops.mq.insert_requests(hctx, &list, at_head);//dd_insert_requests()，把req插入IO算法队列
		
	} else {//如果调度算法没有定义insert_requests，一般不会成立吧
		spin_lock(&ctx->lock);
        //把req插入到软件队列ctx->rq_list链表,对应的硬件队列hctx->ctx_map里的bit位被置1，表示激活
		__blk_mq_insert_request(hctx, rq, at_head);
		spin_unlock(&ctx->lock);
	}

run:
	if (run_queue)
		blk_mq_run_hw_queue(hctx, async);//启动硬件队列上的req派发到块设备驱动
}


//如果有IO调度算法，则把list(来自plug->mq_list或者其他)链表上的req插入elv的hash队列，mq-deadline算法的还要插入红黑树和fifo队列。
//如果没有IO调度算法，取出plug->mq_list链表的上的req，从硬件队列的blk_mq_tags结构体的tags->bitmap_tags或者tags->nr_reserved_tags
//分配一个空闲tag赋于req->tag，然后调用磁盘驱动queue_rq接口函数把req派发给驱动。如果遇到磁盘驱动硬件忙，则设置硬件队列忙，
//还释放req的tag，然后把这个失败派送的req插入hctx->dispatch链表,如果此时list链表空则同步派发。最后把把list(来自plug->mq_list或者其他)
//链表的上剩余的req插入到软件队列ctx->rq_list链表上，然后执行blk_mq_run_hw_queue()再进行req派发。
void blk_mq_sched_insert_requests(struct request_queue *q,
				  struct blk_mq_ctx *ctx,
				  struct list_head *list, bool run_queue_async)//list临时保存了当前进程plug->mq_list链表上的部分req
{
    //找到ctx->cpu这个CPU编号对应的硬件队列结构
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);
	struct elevator_queue *e = hctx->queue->elevator;//IO调度算法调度器

	if (e && e->aux->ops.mq.insert_requests)
        //尝试将req合并到q->last_merg或者调度算法的hash队列的临近req。合并不了的话，把req插入到deadline调度算法的红黑树和fifo队列，
        //设置req在fifo队列的超时时间。还插入elv调度算法的hash队列。注意，hash队列不是deadline调度算法独有的。
		e->aux->ops.mq.insert_requests(hctx, list, false);//mq-deadline调度算法的走这里dd_insert_requests

	else {//没用IO调度器的走这里
		/*
		 * try to issue requests directly if the hw queue isn't
		 * busy in case of 'none' scheduler, and this way may save
		 * us one extra enqueue & dequeue to sw queue.
		 */
		//硬件队列不能忙，没用IO调度器，不能异步处理，if才成立。否则，就执行下边的代码:再把list上的req插入到软件队列
		if (!hctx->dispatch_busy && !e && !run_queue_async) {
//依次遍历当前进程list(来自plug->mq_list链表或者其他)链表上的req，从硬件队列的blk_mq_tags结构体的tags->bitmap_tags或者tags->nr_reserved_tags
//分配一个空闲tag赋于rq->tag，调用磁盘驱动queue_rq接口函数把req派发给驱动。如果遇到磁盘驱动硬件忙，则设置硬件队列忙，还释放req的tag，
//然后把这个派送失败的req插入hctx->dispatch链表，如果此时list链表空则同步派发。如果遇到req传输完成则执行blk_mq_end_request()统计IO使用率等数据并唤醒进程
			blk_mq_try_issue_list_directly(hctx, list);
            //list临时保存了当前进程plug->mq_list链表上的req，如果list空，应该说明所有的req都派发磁盘驱动了，直接返回收工
			if (list_empty(list))
				return;
		}
        
        //到这里，说明list链表上还有剩余的req没有派发硬件队列传输。这是要把硬件队列没有处理的req插入软件队列呀!
        
        //把list链表上的所有req插入到到软件队列ctx->rq_list链表，然后对list清0，这个list链表源自当前进程的plug链表。每一个req在分配时，
        //req->mq_ctx会指向当前CPU的软件队列，但是真正把req插入到软件队列，看着得执行blk_mq_insert_requests才行呀
		blk_mq_insert_requests(hctx, ctx, list);
	}
    
    //再次启动硬件IO数据派发，又一个重点函数，run_queue_async可以指定异步派发
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
//为硬件队列结构hctx->sched_tags分配blk_mq_tags，一个硬件队列一个blk_mq_tags，然后根据为这个blk_mq_tags分配q->nr_requests个request，
//存于tags->static_rqs[]。这是为调度算法tags分配的request。
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

//针对hctx_idx编号的硬件队列，每一层队列深度都分配request(共分配q->nr_requests个request)赋值于tags->static_rqs[]。
//具体是分配N个page，将page的内存一片片分割成request集合大小。然后tags->static_rqs记录每一个request首地址，
//接着执行nvme_init_request()底层驱动初始化函数,建立request与nvme队列的关系吧
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
    //为硬件队列结构hctx->sched_tags分配blk_mq_tags，一个硬件队列一个blk_mq_tags，然后根据为这个blk_mq_tags分配q->nr_requests
    //个request，存于tags->static_rqs[]
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
