/*
 * Tag allocation using scalable bitmaps. Uses active queue tracking to support
 * fairer distribution of tags between multiple submitters when a shared tag map
 * is used.
 *
 * Copyright (C) 2013-2014 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/blk-mq.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-tag.h"

bool blk_mq_has_free_tags(struct blk_mq_tags *tags)
{
	if (!tags)
		return true;

	return sbitmap_any_bit_clear(&tags->bitmap_tags.sb);
}

/*
 * If a previously inactive queue goes active, bump the active user count.
 */
bool __blk_mq_tag_busy(struct blk_mq_hw_ctx *hctx)
{
	if (!test_bit(BLK_MQ_S_TAG_ACTIVE, &hctx->state) &&
	    !test_and_set_bit(BLK_MQ_S_TAG_ACTIVE, &hctx->state))
		atomic_inc(&hctx->tags->active_queues);

	return true;
}

/*
 * Wakeup all potentially sleeping on tags
 */
void blk_mq_tag_wakeup_all(struct blk_mq_tags *tags, bool include_reserve)
{
	sbitmap_queue_wake_all(&tags->bitmap_tags);
	if (include_reserve)
		sbitmap_queue_wake_all(&tags->breserved_tags);
}

/*
 * If a previously busy queue goes inactive, potential waiters could now
 * be allowed to queue. Wake them up and check.
 */
void __blk_mq_tag_idle(struct blk_mq_hw_ctx *hctx)
{
	struct blk_mq_tags *tags = hctx->tags;

	if (!test_and_clear_bit(BLK_MQ_S_TAG_ACTIVE, &hctx->state))
		return;

	atomic_dec(&tags->active_queues);

	blk_mq_tag_wakeup_all(tags, false);
}

/*
 * For shared tag users, we track the number of currently active users
 * and attempt to provide a fair share of the tag depth for each of them.
 */
static inline bool hctx_may_queue(struct blk_mq_hw_ctx *hctx,
				  struct sbitmap_queue *bt)
{
	unsigned int depth, users;

	if (!hctx || !(hctx->flags & BLK_MQ_F_TAG_SHARED))
		return true;
	if (!test_bit(BLK_MQ_S_TAG_ACTIVE, &hctx->state))
		return true;

	/*
	 * Don't try dividing an ant
	 */
	if (bt->sb.depth == 1)
		return true;

	users = atomic_read(&hctx->tags->active_queues);
	if (!users)
		return true;

	/*
	 * Allow at least some tags
	 */
	depth = max((bt->sb.depth + users - 1) / users, 4U);
	return atomic_read(&hctx->nr_active) < depth;
}
//根据sbitmap_queue得到blk_mq_tags结构体的static_rqs[]数组里空闲的request的数组下标，返回这个下标，实际这个下标不是static_rqs[]
//真正的数组下标，加一个偏移值才是
static int __blk_mq_get_tag(struct blk_mq_alloc_data *data,
			    struct sbitmap_queue *bt)
{
	if (!(data->flags & BLK_MQ_REQ_INTERNAL) &&
	    !hctx_may_queue(data->hctx, bt))
		return -1;
	if (data->shallow_depth)
		return __sbitmap_queue_get_shallow(bt, data->shallow_depth);
	else
		return __sbitmap_queue_get(bt);
}
/*
1 关于硬件队列的tags->breserved_tags、tags->bitmap_tags、static_rqs[]、nr_reserved_tags一直很疑惑，现在应该搞清楚了。当submio时执行
blk_mq_make_request->blk_mq_sched_get_request，从硬件队列相关的blk_mq_tags结构的static_rqs[]数组里得到空闲的req。其实本质是:
先得到硬件队列hctx，然后根据有无调度算法返回该硬件唯一绑定的hctx->sched_tags或者hctx->tags，即blk_mq_get_tag()中的
struct blk_mq_tags *tags = blk_mq_tags_from_data(data)。现在有了blk_mq_tags，接着从tags->breserved_tags或者tags->bitmap_tags先分配
一个空闲tag，这个tag指定了本次分配的req在static_rqs[]数组的下标，下标就是blk_mq_get_tag()的返回值tag + tag_offset。
tags->breserved_tags或者tags->bitmap_tags是struct sbitmap_queue结构，应该可以理解成就是一个个bit位吧，
有点像ext4文件系统的inode bitmap，每一个bit表示一个tag，该bit表示的tag被分配了就置1，分配tag应该就是从tags->breserved_tags或者
tags->bitmap_tags查找bit为是0的哪个?应该是这个意思。然后赋值req->tag =tag ，hctx->tags->rqs[req->tag] = req。

2 从tags->bitmap_tags或者tags->breserved_tags分配的tag，其实是一个数字，表示本次分配的reg在static_rqs[]数组的下标。

3 关于tags->breserved_tags和tags->bitmap_tags，
看blk_mq_get_tag()函数if (data->flags & BLK_MQ_REQ_RESERVED)成立，则使用tags->breserved_tags，什么条件成立呢?

submio执行blk_mq_make_request->blk_mq_sched_get_request，使用了调度器，则data->flags |= BLK_MQ_REQ_INTERNAL。

然后执行blk_mq_get_tag(),if (data->flags & BLK_MQ_REQ_RESERVED不成立，执行bt = &tags->bitmap_tags和tag_offset = tags->nr_reserved_tags，
然后从tags->bitmap_tags分配一个tag，然后tags->nr_reserved_tags+tag 是本次分配的req在static_rqs[]的下标，啥意思?static_rqs[]数组的
0~tags->nr_reserved_tags位置都是reserved tag，tags->nr_reserved_tags后边的才是非reserved tag。接着执行__blk_mq_alloc_request(),
因为if (data->flags & BLK_MQ_REQ_INTERNAL)成立，则__rq_aux(rq, data->q)->internal_tag = tag，这个tag大于tags->nr_reserved_tags，
这点很重要，稍后就有用。然后经过漫长的旅途，要把该req派送给硬件驱动了，需执行blk_mq_dispatch_rq_list()。但是因为磁盘驱动硬件繁忙，
该req没有派发成功。则要执行__blk_mq_requeue_request(req)，把该req占用的tag从tags->bitmap_tags从释放掉，然后把req放入hctx->dispatch
链表启动异步派发。最终还会执行blk_mq_dispatch_rq_list()->blk_mq_get_driver_tag()，
if (blk_mq_tag_is_reserved(data.hctx->sched_tags, rq_aux(rq)->internal_tag))不成立，不会执行data.flags |= BLK_MQ_REQ_RESERVED，
接着执行blk_mq_get_tag()，跟上边的流程一样，还是bt = &tags->bitmap_tags 从bitmap_tags分配tag。

4如果submio执行blk_mq_make_request->blk_mq_sched_get_request，没有使用调度器，不会执行data->flags |= BLK_MQ_REQ_INTERNAL，

然后执行blk_mq_get_tag(),if (data->flags & BLK_MQ_REQ_RESERVED不成立，执行bt = &tags->bitmap_tags和tag_offset = tags->nr_reserved_tags，
然后从tags->bitmap_tags分配一个tag，然后tags->nr_reserved_tags+tag 是本次分配的req在static_rqs[]的下标。接着执行
__blk_mq_alloc_request(),因为if (data->flags & BLK_MQ_REQ_INTERNAL)不不不不成立，则__rq_aux(rq, data->q)->internal_tag = -1，
这样tag小于tags->nr_reserved_tags，这点很重要，稍后就有用。然后经过漫长的旅途，要把该req派送给硬件驱动了，需执行
blk_mq_dispatch_rq_list()。但是因为磁盘驱动硬件繁忙，该req没有派发成功。则要执行__blk_mq_requeue_request(req)，把该req占用的
tag从tags->bitmap_tags从释放掉，然后把req放入hctx->dispatch链表启动异步派发。最终还会执行blk_mq_dispatch_rq_list()->
blk_mq_get_driver_tag()，if (blk_mq_tag_is_reserved(data.hctx->sched_tags, rq_aux(rq)->internal_tag))成立成立成立成立成立，
则执行data.flags |= BLK_MQ_REQ_RESERVED，接着执行blk_mq_get_tag()，因为if (data->flags & BLK_MQ_REQ_RESERVED) 成立，则
bt = &tags->breserved_tags和tag_offset = 0，则本次是从tags->breserved_tags这个reserved tag分配tag，并且tag+0是本次分配的req在
static_rqs[]数组的下标。也就是说，static_rqs[]数组的0~tags->nr_reserved_tags是reserved tag的req的数组下标，tags->nr_reserved_tags以上
的tag是非reserved tag的req的数组下标。

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!理解错了，看看这个理解req从初次分配，req始终没有变，但是tag分配释放再分配，tag早变了，tag还能唯一
表示req在static_rqs[]数组的位置吗，不行吧req是固定的，但是tag变来变去

5 凡是执行blk_mq_get_driver_tag()的情况，都是该req在第一次派发时遇到硬件队列繁忙，就把tag释放了，然后rq->tag=-1。
接着启动异步派发，才会执行该函数

6 tag和req是绑定的，在submio执行blk_mq_make_request->blk_mq_sched_get_request时，是先从硬件队列blk_mq_tags分配tag，然后从blk_mq_tags
的static_rqs[tag]得到req。之后在进行req传输时，遇到磁盘驱动硬件繁忙，则会执行__blk_mq_requeue_request(req)把req的tag释放掉，然后等
异步派发req时，则会执行blk_mq_get_driver_tag()重新为req分配tag。
*/

//从硬件队列的blk_mq_tags结构体的tags->bitmap_tags或者tags->nr_reserved_tags分配一个空闲tag，一个req必须分配一个tag才能IO传输。
//分配失败则启动硬件IO数据派发，休眠，后再尝试从blk_mq_tags结构体的tags->bitmap_tags或者tags->nr_reserved_tags分配一个空闲tag。
unsigned int blk_mq_get_tag(struct blk_mq_alloc_data *data)
{
    //使用调度器时返回硬件队列的hctx->sched_tags，无调度器时返回硬件队列的hctx->tags。返回的是硬件队列唯一对应的的blk_mq_tags
	struct blk_mq_tags *tags = blk_mq_tags_from_data(data);
	struct sbitmap_queue *bt;
	struct sbq_wait_state *ws;
	DEFINE_WAIT(wait);
	unsigned int tag_offset;
	bool drop_ctx;
	int tag;

	if (data->flags & BLK_MQ_REQ_RESERVED) {//使用预留tag
		if (unlikely(!tags->nr_reserved_tags)) {
			WARN_ON_ONCE(1);
			return BLK_MQ_TAG_FAIL;
		}
		bt = &tags->breserved_tags;
		tag_offset = 0;
	} else {//不使用预留tag
	
	    //返回blk_mq_tags的bitmap_tags
		bt = &tags->bitmap_tags;
        //应该是static_rqs[]里空闲的request的数组下标偏移，见该函数最后
		tag_offset = tags->nr_reserved_tags;
	}
    
//从硬件队列的blk_mq_tags结构体的tags->bitmap_tags或者tags->nr_reserved_tags分配一个空闲tag。tag表明了req在static_rqs[]的数组下标。
//实际tag并不是req在static_rqs[]数组的下标，真正的数组下标，加一个偏移值tag_offset才是。返回-1说明没有空闲tag，就会执行下边的循环，
//启动磁盘硬件传输，以腾出空闲的tag。一个tag就是一个req，req传输前必须得分配tag，分配tag本质是从硬件队列blk_mq_tags得到空闲req。
	tag = __blk_mq_get_tag(data, bt);
	if (tag != -1)
		goto found_tag;

	if (data->flags & BLK_MQ_REQ_NOWAIT)//显然这是不运行等待
		return BLK_MQ_TAG_FAIL;

    //走到这一步，说明硬件队列有关的blk_mq_tags里没有空闲的request可分配，那就会陷入休眠等待，并且执行blk_mq_run_hw_queue
    //启动IO 数据传输，传输完成后可以释放出request，达到分配request的目的

	ws = bt_wait_ptr(bt, data->hctx);//获取硬件队列唯一对应的wait_queue_head_t等待队列头，我去，这也是硬件队列唯一对应的
	drop_ctx = data->ctx == NULL;
	do {
		struct sbitmap_queue *bt_prev;

		prepare_to_wait(&ws->wait, &wait, TASK_UNINTERRUPTIBLE);//在ws->wait等待队列准备休眠
        
        //再次尝试从blk_mq_tags结构体里分配空闲tag
		tag = __blk_mq_get_tag(data, bt);
		if (tag != -1)
			break;

		/*
		 * We're out of tags on this hardware queue, kick any
		 * pending IO submits before going to sleep waiting for
		 * some to complete.
		 */
		//启动磁盘硬件队列IO同步传输，以腾出空闲req
		blk_mq_run_hw_queue(data->hctx, false);

		/*
		 * Retry tag allocation after running the hardware queue,
		 * as running the queue may also have found completions.
		 */
		//再次尝试从blk_mq_tags结构体里分配空闲tag
		tag = __blk_mq_get_tag(data, bt);
		if (tag != -1)
			break;

		if (data->ctx)
			blk_mq_put_ctx(data->ctx);

		bt_prev = bt;
        //休眠调度
		io_schedule();

        //奇怪，再次获取软件队列和硬件队列，为什么?????????上边启动了硬件IO数据派发，等io_schedule()调度后再被唤醒，进程所处CPU有
        //可能会变，所以要根据进程所处CPU获取对应的软件队列，再获取对应的硬件队列
		data->ctx = blk_mq_get_ctx(data->q);
		data->hctx = blk_mq_map_queue(data->q, data->ctx->cpu);
        
        //使用调度器时返回硬件队列的hctx->sched_tags，无调度器时返回硬件队列的hctx->tags
		tags = blk_mq_tags_from_data(data);
		if (data->flags & BLK_MQ_REQ_RESERVED)
			bt = &tags->breserved_tags;
		else//再次获取bitmap_tags，流程跟前边一模一样
			bt = &tags->bitmap_tags;

        //休眠后唤醒，完成休眠
		finish_wait(&ws->wait, &wait);

		/*
		 * If destination hw queue is changed, fake wake up on
		 * previous queue for compensating the wake up miss, so
		 * other allocations on previous queue won't be starved.
		 */
		if (bt != bt_prev)
			sbitmap_queue_wake_up(bt_prev);

        //再次根据硬件队列获取唯一对应的wait_queue_head_t等待队列头
		ws = bt_wait_ptr(bt, data->hctx);
	} while (1);

	if (drop_ctx && data->ctx)
		blk_mq_put_ctx(data->ctx);

	finish_wait(&ws->wait, &wait);

found_tag:
    //看到没有，tag+tag_offset才是本次分配的空闲request在static_rqs[]数组的真正下标
	return tag + tag_offset;
}
//tags->bitmap_tags中按照req->tag这个tag编号释放tag
void blk_mq_put_tag(struct blk_mq_hw_ctx *hctx, struct blk_mq_tags *tags,
		    struct blk_mq_ctx *ctx, unsigned int tag)
{
	if (!blk_mq_tag_is_reserved(tags, tag)) {
        //tag - tags->nr_reserved_tags后才是该tag在tags->bitmap_tags的真是位置
		const int real_tag = tag - tags->nr_reserved_tags;

		BUG_ON(real_tag >= tags->nr_tags);
		sbitmap_queue_clear(&tags->bitmap_tags, real_tag, ctx->cpu);
	} else {
		BUG_ON(tag >= tags->nr_reserved_tags);
		sbitmap_queue_clear(&tags->breserved_tags, tag, ctx->cpu);
	}
}

struct bt_iter_data {
	struct blk_mq_hw_ctx *hctx;
	busy_iter_fn *fn;
	void *data;
	bool reserved;
};

static bool bt_iter(struct sbitmap *bitmap, unsigned int bitnr, void *data)
{
	struct bt_iter_data *iter_data = data;
	struct blk_mq_hw_ctx *hctx = iter_data->hctx;
	struct blk_mq_tags *tags = hctx->tags;
	bool reserved = iter_data->reserved;
	struct request *rq;

	if (!reserved)
		bitnr += tags->nr_reserved_tags;
	rq = tags->rqs[bitnr];

	/*
	 * We can hit rq == NULL here, because the tagging functions
	 * test and set the bit before assining ->rqs[].
	 */
	if (rq && rq->q == hctx->queue)
		iter_data->fn(hctx, rq, iter_data->data, reserved);
	return true;
}

static void bt_for_each(struct blk_mq_hw_ctx *hctx, struct sbitmap_queue *bt,
			busy_iter_fn *fn, void *data, bool reserved)
{
	struct bt_iter_data iter_data = {
		.hctx = hctx,
		.fn = fn,
		.data = data,
		.reserved = reserved,
	};

	sbitmap_for_each_set(&bt->sb, bt_iter, &iter_data);
}

struct bt_tags_iter_data {
	struct blk_mq_tags *tags;
	busy_tag_iter_fn *fn;
	void *data;
	bool reserved;
};

static bool bt_tags_iter(struct sbitmap *bitmap, unsigned int bitnr, void *data)
{
	struct bt_tags_iter_data *iter_data = data;
	struct blk_mq_tags *tags = iter_data->tags;
	bool reserved = iter_data->reserved;
	struct request *rq;

	if (!reserved)
		bitnr += tags->nr_reserved_tags;

	/*
	 * We can hit rq == NULL here, because the tagging functions
	 * test and set the bit before assining ->rqs[].
	 */
	rq = tags->rqs[bitnr];
	if (rq)
		iter_data->fn(rq, iter_data->data, reserved);

	return true;
}

static void bt_tags_for_each(struct blk_mq_tags *tags, struct sbitmap_queue *bt,
			     busy_tag_iter_fn *fn, void *data, bool reserved)
{
	struct bt_tags_iter_data iter_data = {
		.tags = tags,
		.fn = fn,
		.data = data,
		.reserved = reserved,
	};

	if (tags->rqs)
		sbitmap_for_each_set(&bt->sb, bt_tags_iter, &iter_data);
}

static void blk_mq_all_tag_busy_iter(struct blk_mq_tags *tags,
		busy_tag_iter_fn *fn, void *priv)
{
	if (tags->nr_reserved_tags)
		bt_tags_for_each(tags, &tags->breserved_tags, fn, priv, true);
	bt_tags_for_each(tags, &tags->bitmap_tags, fn, priv, false);
}

void blk_mq_tagset_busy_iter(struct blk_mq_tag_set *tagset,
		busy_tag_iter_fn *fn, void *priv)
{
	int i;

	for (i = 0; i < tagset->nr_hw_queues; i++) {
		if (tagset->tags && tagset->tags[i])
			blk_mq_all_tag_busy_iter(tagset->tags[i], fn, priv);
	}
}
EXPORT_SYMBOL(blk_mq_tagset_busy_iter);

int blk_mq_reinit_tagset(struct blk_mq_tag_set *set)
{
	int i, j, ret = 0;

	if (!set->ops->aux_ops || !set->ops->aux_ops->reinit_request)
		goto out;

	for (i = 0; i < set->nr_hw_queues; i++) {
		struct blk_mq_tags *tags = set->tags[i];

		if (!tags)
			continue;

		for (j = 0; j < tags->nr_tags; j++) {
			if (!tags->static_rqs[j])
				continue;

			ret = set->ops->aux_ops->reinit_request(set->driver_data,
						tags->static_rqs[j]);
			if (ret)
				goto out;
		}
	}

out:
	return ret;
}
EXPORT_SYMBOL_GPL(blk_mq_reinit_tagset);

void blk_mq_queue_tag_busy_iter(struct request_queue *q, busy_iter_fn *fn,
		void *priv)
{
	struct blk_mq_hw_ctx *hctx;
	int i;


	queue_for_each_hw_ctx(q, hctx, i) {
		struct blk_mq_tags *tags = hctx->tags;

		/*
		 * If not software queues are currently mapped to this
		 * hardware queue, there's nothing to check
		 */
		if (!blk_mq_hw_queue_mapped(hctx))
			continue;

		if (tags->nr_reserved_tags)
			bt_for_each(hctx, &tags->breserved_tags, fn, priv, true);
		bt_for_each(hctx, &tags->bitmap_tags, fn, priv, false);
	}

}

static int bt_alloc(struct sbitmap_queue *bt, unsigned int depth,
		    bool round_robin, int node)
{
	return sbitmap_queue_init_node(bt, depth, -1, round_robin, GFP_KERNEL,
				       node);
}

static struct blk_mq_tags *blk_mq_init_bitmap_tags(struct blk_mq_tags *tags,
						   int node, int alloc_policy)
{
	unsigned int depth = tags->nr_tags - tags->nr_reserved_tags;
	bool round_robin = alloc_policy == BLK_TAG_ALLOC_RR;

	if (bt_alloc(&tags->bitmap_tags, depth, round_robin, node))
		goto free_tags;
	if (bt_alloc(&tags->breserved_tags, tags->nr_reserved_tags, round_robin,
		     node))
		goto free_bitmap_tags;

	return tags;
free_bitmap_tags:
	sbitmap_queue_free(&tags->bitmap_tags);
free_tags:
	kfree(tags);
	return NULL;
}
//分配一个blk_mq_tags结构，设置其成员nr_reserved_tags和nr_tags，分配blk_mq_tags的bitmap_tags、breserved_tags结构
struct blk_mq_tags *blk_mq_init_tags(unsigned int total_tags,
				     unsigned int reserved_tags,
				     int node, int alloc_policy)
{
	struct blk_mq_tags *tags;
    //total_tags竟然是set->queue_depth
	if (total_tags > BLK_MQ_TAG_MAX) {
		pr_err("blk-mq: tag depth too large\n");
		return NULL;
	}
    //分配一个blk_mq_tags结构，设置其成员nr_reserved_tags和nr_tags
	tags = kzalloc_node(sizeof(*tags), GFP_KERNEL, node);
	if (!tags)
		return NULL;

	tags->nr_tags = total_tags;
	tags->nr_reserved_tags = reserved_tags;
    //分配blk_mq_tags的bitmap_tags、breserved_tags结构
	return blk_mq_init_bitmap_tags(tags, node, alloc_policy);
}

void blk_mq_free_tags(struct blk_mq_tags *tags)
{
	sbitmap_queue_free(&tags->bitmap_tags);
	sbitmap_queue_free(&tags->breserved_tags);
	kfree(tags);
}

int blk_mq_tag_update_depth(struct blk_mq_hw_ctx *hctx,
			    struct blk_mq_tags **tagsptr, unsigned int tdepth,
			    bool can_grow)
{
	struct blk_mq_tags *tags = *tagsptr;

	if (tdepth <= tags->nr_reserved_tags)
		return -EINVAL;

	tdepth -= tags->nr_reserved_tags;

	/*
	 * If we are allowed to grow beyond the original size, allocate
	 * a new set of tags before freeing the old one.
	 */
	if (tdepth > tags->nr_tags) {
		struct blk_mq_tag_set *set = hctx->queue->tag_set;
		struct blk_mq_tags *new;
		bool ret;

		if (!can_grow)
			return -EINVAL;

		/*
		 * We need some sort of upper limit, set it high enough that
		 * no valid use cases should require more.
		 */
		if (tdepth > 16 * BLKDEV_MAX_RQ)
			return -EINVAL;

		new = blk_mq_alloc_rq_map(set, hctx->queue_num, tdepth, 0);
		if (!new)
			return -ENOMEM;
		ret = blk_mq_alloc_rqs(set, new, hctx->queue_num, tdepth);
		if (ret) {
			blk_mq_free_rq_map(new);
			return -ENOMEM;
		}

		blk_mq_free_rqs(set, *tagsptr, hctx->queue_num);
		blk_mq_free_rq_map(*tagsptr);
		*tagsptr = new;
	} else {
		/*
		 * Don't need (or can't) update reserved tags here, they
		 * remain static and should never need resizing.
		 */
		sbitmap_queue_resize(&tags->bitmap_tags, tdepth);
	}

	return 0;
}

/**
 * blk_mq_unique_tag() - return a tag that is unique queue-wide
 * @rq: request for which to compute a unique tag
 *
 * The tag field in struct request is unique per hardware queue but not over
 * all hardware queues. Hence this function that returns a tag with the
 * hardware context index in the upper bits and the per hardware queue tag in
 * the lower bits.
 *
 * Note: When called for a request that is queued on a non-multiqueue request
 * queue, the hardware context index is set to zero.
 */
u32 blk_mq_unique_tag(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct blk_mq_hw_ctx *hctx;
	int hwq = 0;

	if (q->mq_ops) {
		hctx = blk_mq_map_queue(q, rq->mq_ctx->cpu);
		hwq = hctx->queue_num;
	}

	return (hwq << BLK_MQ_UNIQUE_TAG_BITS) |
		(rq->tag & BLK_MQ_UNIQUE_TAG_MASK);
}
EXPORT_SYMBOL(blk_mq_unique_tag);
