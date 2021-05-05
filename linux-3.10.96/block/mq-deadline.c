/*
 *  MQ Deadline i/o scheduler - adaptation of the legacy deadline scheduler,
 *  for the blk-mq scheduling framework
 *
 *  Copyright (C) 2016 Jens Axboe <axboe@kernel.dk>
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/rbtree.h>
#include <linux/sbitmap.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-tag.h"
#include "blk-mq-sched.h"

/*
 * See Documentation/block/deadline-iosched.txt
 */
static const int read_expire = HZ / 2;  /* max time before a read is submitted. */
static const int write_expire = 5 * HZ; /* ditto for writes, these limits are SOFT! */
static const int writes_starved = 2;    /* max times reads can starve a write */
static const int fifo_batch = 16;       /* # of sequential requests treated as one
				     by the above parameters. For throughput. */

struct deadline_data {//这是多队列的，单队列见deadline-iosched.c
	/*
	 * run time data
	 */

	/*
	 * requests (deadline_rq s) are present on both sort_list and fifo_list
	 */
	struct rb_root sort_list[2];
	struct list_head fifo_list[2];

	/*
	 * next in sort order. read, write or both are NULL
	 */
	struct request *next_rq[2];
	unsigned int batching;		/* number of sequential requests made */
	unsigned int starved;		/* times reads have starved writes */

	/*
	 * settings that change how the i/o scheduler behaves
	 */
	int fifo_expire[2];
	int fifo_batch;
	int writes_starved;
	int front_merges;//应该在deadline_init_queue()中被赋值1

	spinlock_t lock;
    //dd_insert_request中，把req添加到该dispatch 队列
	struct list_head dispatch;
};

static inline struct rb_root *
deadline_rb_root(struct deadline_data *dd, struct request *rq)
{
	return &dd->sort_list[rq_data_dir(rq)];
}

/*
 * get the request after `rq' in sector-sorted order
 */
static inline struct request *
deadline_latter_request(struct request *rq)
{
	struct rb_node *node = rb_next(&rq->rb_node);

	if (node)
		return rb_entry_rq(node);

	return NULL;
}

static void
deadline_add_rq_rb(struct deadline_data *dd, struct request *rq)
{
	struct rb_root *root = deadline_rb_root(dd, rq);
    //按照req的磁盘起始地址把req添加到红黑树队列里，这个红黑树里req的排列规则是，谁的磁盘起始地址小谁靠左
	elv_rb_add(root, rq);
}
//给dd->next_rq[]赋值req的下一个req，下一次从红黑树选择req发给驱动时用到。并且把req从红黑树中剔除
static inline void
deadline_del_rq_rb(struct deadline_data *dd, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);

    //给dd->next_rq[]赋值req的下一个req,下一次从红黑树选择req发给驱动时，直接使用这个nedd->next_rq[]xt_rq
    if (dd->next_rq[data_dir] == rq)
		dd->next_rq[data_dir] = deadline_latter_request(rq);
    
    //deadline_rb_root(dd, rq)是取出调度算法的读或者写红黑树队列头rb_root，然后把req从这个红黑树队列剔除掉
	elv_rb_del(deadline_rb_root(dd, rq), rq);
}

/*
 * remove rq from rbtree and fifo.
 */
static void deadline_remove_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	list_del_init(&rq->queuelist);

	/*
	 * We might not be on the rbtree, if we are doing an insert merge
	 */
	if (!RB_EMPTY_NODE(&rq->rb_node))
		deadline_del_rq_rb(dd, rq);

	elv_rqhash_del(q, rq);
	if (q->last_merge == rq)
		q->last_merge = NULL;
}

static void dd_request_merged(struct request_queue *q, struct request *req,
			      int type)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	/*
	 * if the merge was a front merge, we need to reposition request
	 */
	if (type == ELEVATOR_FRONT_MERGE) {
		elv_rb_del(deadline_rb_root(dd, req), req);
		deadline_add_rq_rb(dd, req);
	}
}
//在fifo队列里，把req移动到next节点的位置，更新req的超时时间。从fifo队列和红黑树剔除next,还更新dd->next_rq[]赋值next的下一个req
static void dd_merged_requests(struct request_queue *q, struct request *req,
			       struct request *next)
{
	/*
	 * if next expires before rq, assign its expire time to rq
	 * and move into next position (next will be deleted) in fifo
	 */
	//如果next的超时时间早于req，更新到req超时时间里
	if (!list_empty(&req->queuelist) && !list_empty(&next->queuelist)) {
		if (time_before((unsigned long)next->fifo_time,
				(unsigned long)req->fifo_time)) {
		    //把req移动到next节点的位置，这个链表是fifo队列
			list_move(&req->queuelist, &next->queuelist);
            //更新req的超时时间
			req->fifo_time = next->fifo_time;
		}
	}

	/*
	 * kill knowledge of next, this one is a goner
	 */
	//从fifo队列剔除next,从红黑树剔除next。给dd->next_rq[]赋值next的下一个req，下一次从红黑树选择req发给驱动时用到
	deadline_remove_request(q, next);
}

/*
 * move an entry to dispatch queue
 */
//从红黑树中设置req的next req给dd->next_rq[data_dir],把req从fifo队列和红黑树队列剔除
static void
deadline_move_request(struct deadline_data *dd, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);

	dd->next_rq[READ] = NULL;
	dd->next_rq[WRITE] = NULL;
    //从红黑树中设置req的next req给dd->next_rq[data_dir]
	dd->next_rq[data_dir] = deadline_latter_request(rq);

	/*
	 * take it off the sort and fifo list
	 */
	//只是把req从fifo队列和红黑树队列剔除
	deadline_remove_request(rq->q, rq);
}

/*
 * deadline_check_fifo returns 0 if there are no expired requests on the fifo,
 * 1 otherwise. Requires !list_empty(&dd->fifo_list[data_dir])
 */
static inline int deadline_check_fifo(struct deadline_data *dd, int ddir)
{
	struct request *rq = rq_entry_fifo(dd->fifo_list[ddir].next);

	/*
	 * rq is expired!
	 */
	if (time_after_eq(jiffies, (unsigned long)rq->fifo_time))
		return 1;

	return 0;
}

/*
 * deadline_dispatch_requests selects the best request according to
 * read/write expire, fifo_batch, etc
 */
//mq-deadline调度算法核心派发req函数，该函数与单通道deadline派发算法函数deadline_dispatch_requests原理基本一致。
//执行deadline派发函数，从fifo或者红黑树队列选择待派发给驱动传输的req返回。然后设置新的next_rq，并把req从fifo队列和红黑树队列剔除，
//req来源有:上次派发设置的next_rq;read req派发过多而选择的write req;fifo 队列上超时要传输的req，统筹兼顾，有固定策略
static struct request *__dd_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct deadline_data *dd = hctx->queue->elevator->elevator_data;
	struct request *rq;
	bool reads, writes;
	int data_dir;

	if (!list_empty(&dd->dispatch)) {
        //如果dd->dispatch队列有req要派发，取出来直接后直接返回，我去，这个真简单
		rq = list_first_entry(&dd->dispatch, struct request, queuelist);
		list_del_init(&rq->queuelist);
		goto done;
	}
    //deadline调度算法fifo读队列不空reads为1
	reads = !list_empty(&dd->fifo_list[READ]);
    //deadline调度算法fifo写队列不空writes为1
	writes = !list_empty(&dd->fifo_list[WRITE]);

	/*
	 * batches are currently reads XOR writes
	 */
	//每次从红黑树选取一个req发给驱动传输，这个req的下一个req保存在next_rq，现在又向驱动发送req传输，先从next_rq取出req
	if (dd->next_rq[WRITE])
		rq = dd->next_rq[WRITE];
	else
		rq = dd->next_rq[READ];

//如果dd->batching大于等于dd->fifo_batch，不再使用next_rq，否则会一直只向后使用红黑树队列的req向驱动发送传输，队列前边的req得不到发送
	if (rq && dd->batching < dd->fifo_batch)
		/* we have a next request are still entitled to batch */
		goto dispatch_request;

	/*
	 * at this point we are not running a batch. select the appropriate
	 * data direction (read / write)
	 */
    //这应该是选择选择read或write req，因为一直选择read req给驱动传输，那write req就starve饿死了
	if (reads) {
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[READ]));
        //有write req要传送给驱动，并且write req被饥饿次数达到上限，就强制选择跳转选择write req
        //防止一直选择read req给驱动传输，write req得不到选择而starve饥饿，每次write req得不到选择而饥饿则starved++，
        //writes_starved是饥饿的次数上限，starved大于writes_starved，就强制选择write req
		if (writes && (dd->starved++ >= dd->writes_starved))
			goto dispatch_writes;

         //否则下面选择read req
		data_dir = READ;

		goto dispatch_find_request;
	}

	/*
	 * there are either no reads or writes have been starved
	 */

	if (writes) {
dispatch_writes:
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[WRITE]));
        //dd->starved清0
		dd->starved = 0;
        //下面选择write req，就一个赋值操作
		data_dir = WRITE;

		goto dispatch_find_request;
	}

	return NULL;

dispatch_find_request:
	/*
	 * we are not running a batch, find best request for selected data_dir
	 */
	//deadline_check_fifo如果deadline fifo队列有超时的req要传输返回1，或者next_rq没有暂存req，那就从fifo队列头取出req
	if (deadline_check_fifo(dd, data_dir) || !dd->next_rq[data_dir]) {
		/*
		 * A deadline has expired, the last request was in the other
		 * direction, or we have run out of higher-sectored requests.
		 * Start again from the request with the earliest expiry time.
		 */
		//取出fifo队列头的req，最早入fifo队列的req，最早入队的req当然更容易超时
		rq = rq_entry_fifo(dd->fifo_list[data_dir].next);
	} else {
		/*
		 * The last req was the same dir and we have a next request in
		 * sort order. No expired requests so continue on from here.
		 */
		//否则直接取出next_rq暂存的req，data_dir由前边赋值读或写
		rq = dd->next_rq[data_dir];
	}

	dd->batching = 0;

dispatch_request://调到这里，req直接来自next_rq或者fifo队列，这个req就要被发给驱动传输了
	/*
	 * rq is the selected appropriate request.
	 */
	//batching加1
	dd->batching++;

    //从红黑树中设置req的next req给dd->next_rq[data_dir],把req从fifo队列和红黑树队列剔除
	deadline_move_request(dd, rq);
done:
	rq->cmd_flags |= REQ_STARTED;
	return rq;
}

static struct request *dd_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct deadline_data *dd = hctx->queue->elevator->elevator_data;
	struct request *rq;

	spin_lock(&dd->lock);

 //执行deadline算法派发函数，从fifo或者红黑树队列选择待派的req返回。然后设置新的next_rq，并把req从fifo队列和红黑树队列剔除，
 //req来源有:上次派发设置的next_rq;read req派发过多而选择的write req;fifo 队列上超时要传输的req，统筹兼顾，有固定策略
	rq = __dd_dispatch_request(hctx);
	spin_unlock(&dd->lock);

	return rq;
}

static void dd_exit_queue(struct elevator_queue *e)
{
	struct deadline_data *dd = e->elevator_data;

	BUG_ON(!list_empty(&dd->fifo_list[READ]));
	BUG_ON(!list_empty(&dd->fifo_list[WRITE]));

	kfree(dd);
}

/*
 * initialize elevator private data (deadline_data).
 */
static int dd_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct deadline_data *dd;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	dd = kzalloc_node(sizeof(*dd), GFP_KERNEL, q->node);
	if (!dd) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	eq->elevator_data = dd;

	INIT_LIST_HEAD(&dd->fifo_list[READ]);
	INIT_LIST_HEAD(&dd->fifo_list[WRITE]);
	dd->sort_list[READ] = RB_ROOT;
	dd->sort_list[WRITE] = RB_ROOT;
	dd->fifo_expire[READ] = read_expire;
	dd->fifo_expire[WRITE] = write_expire;
	dd->writes_starved = writes_starved;
	dd->front_merges = 1;
	dd->fifo_batch = fifo_batch;
	spin_lock_init(&dd->lock);
	INIT_LIST_HEAD(&dd->dispatch);

	q->elevator = eq;
	return 0;
}

static int dd_request_merge(struct request_queue *q, struct request **rq,
			    struct bio *bio)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	sector_t sector = bio_end_sector(bio);
	struct request *__rq;

	if (!dd->front_merges)
		return ELEVATOR_NO_MERGE;
    
    //该函数是在调度算法的 读或写红黑树队列里，遍历req,找到req起始扇区地址等于bio_end_sector(bio)的req返回，否则返回NULL
	__rq = elv_rb_find(&dd->sort_list[bio_data_dir(bio)], sector);
	if (__rq) {
		BUG_ON(sector != blk_rq_pos(__rq));
    //如果找到匹配的req，说明bio的扇区结束地址等于req的扇区起始地址，则返回前项合并
		if (elv_bio_merge_ok(__rq, bio)) {
			*rq = __rq;
			return ELEVATOR_FRONT_MERGE;
		}
	}

	return ELEVATOR_NO_MERGE;
}
//在IO调度器队列里查找是否有可以合并的req，找到则可以bio后项或前项合并到req，还会触发二次合并，还会对合并后的req在IO调度算法队列里重新排序
//这个合并跟软件队列和硬件队列没有半毛钱的关系吧
static bool dd_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio)
{
    //磁盘唯一对应的队列request_queue
	struct request_queue *q = hctx->queue;
	struct deadline_data *dd = q->elevator->elevator_data;
	struct request *free = NULL;
	bool ret;

	spin_lock(&dd->lock);
//在IO调度器队列里查找是否有可以合并的req，找到则可以bio后项或前项合并到req，还会触发二次合并，还会对合并后的req在IO调度算法队列里重新排序
	ret = blk_mq_sched_try_merge(q, bio, &free);
	spin_unlock(&dd->lock);

	if (free)
		blk_mq_free_request(free);

	return ret;
}

/*
 * add rq to rbtree and fifo
 */
//尝试将req合并到q->last_merg或者调度算法的hash队列的临近req。合并不了的话，把req插入到deadline调度算法的红黑树和fifo队列，设置req在fifo
//队列的超时时间。还插入elv调度算法的hash队列。注意，hash队列不是deadline调度算法独有的。hash队列和fifo队列到底是不是一回事???????
static void dd_insert_request(struct blk_mq_hw_ctx *hctx, struct request *rq,
			      bool at_head)//at_head:false
{
	struct request_queue *q = hctx->queue;
	struct deadline_data *dd = q->elevator->elevator_data;
	const int data_dir = rq_data_dir(rq);

    //首先尝试将rq后项合并到q->last_merge，再尝试将rq后项合并到hash队列的某一个__rq，合并规则是rq的扇区起始地址等于q->last_merge或__rq
    //的扇区结束地址，都是调用blk_attempt_req_merge()进行合并。并更新IO使用率等数据。如果使用了deadline调度算法，更新合并后的req在
    //hash队列中的位置。还会从fifo队列剔除掉rq，更新dd->next_rq[]赋值rq的下一个req。
	if (blk_mq_sched_try_insert_merge(q, rq))
		return;

	blk_mq_sched_request_inserted(rq);

	if (at_head || rq->cmd_type != REQ_TYPE_FS) {//no,一般req都是REQ_TYPE_FS
	    //如果at_head为TRUE，则把req添加到调度算法的dd->dispatch队列
		if (at_head)
			list_add(&rq->queuelist, &dd->dispatch);
		else
			list_add_tail(&rq->queuelist, &dd->dispatch);
	} else {
	    //按照req的磁盘起始地址把req添加到红黑树队列里，这个红黑树里req的排列规则是，谁的磁盘起始地址小谁靠左
		deadline_add_rq_rb(dd, rq);

		if (rq_mergeable(rq)) {//yes
            //req根据扇区结束地址rq_hash_key(rq)添加到IO调度算法的hash链表里，做hash索引是为了在IO算法队列里搜索可以合并的req时，提高搜索速度
			elv_rqhash_add(q, rq);
			if (!q->last_merge)
				q->last_merge = rq;
		}
		/*到这里，我觉得很奇怪，deadline调度算法，看着有3个队列呀，两个是struct elevator_queue里struct deadline_data
		  的struct rb_root sort_list[2]红黑树队列和struct list_head fifo_list[2]fifo队列，还有一个struct elevator_queue
		  里的hash队列。hash队列是每个调度算法都有的，fifo和红黑树队列是deadline独有的*/
		
		/*
		 * set expire time and add to fifo list
		 */
		//设置req在fifo队列的超时时间
		rq->fifo_time = jiffies + dd->fifo_expire[data_dir];
        //把req插入fifo队列里
		list_add_tail(&rq->queuelist, &dd->fifo_list[data_dir]);
	}
}

static void dd_insert_requests(struct blk_mq_hw_ctx *hctx,
			       struct list_head *list, bool at_head)//at_head:false
{
	struct request_queue *q = hctx->queue;
	struct deadline_data *dd = q->elevator->elevator_data;

	spin_lock(&dd->lock);
    //依次遍历当前进程plug->mq_list链表上的req,
	while (!list_empty(list)) {
		struct request *rq;
        //req从原来的mq_list链表上删除掉
		rq = list_first_entry(list, struct request, queuelist);
		list_del_init(&rq->queuelist);
     //尝试将req合并到q->last_merg或者调度算法的hash队列的临近req。合并不了的话，把req插入到deadline调度算法的红黑树和fifo队列，
     //设置req在fifo队列的超时时间。还插入elv调度算法的hash队列。注意，hash队列不是deadline调度算法独有的。
		dd_insert_request(hctx, rq, at_head);
	}
	spin_unlock(&dd->lock);
}

static bool dd_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct deadline_data *dd = hctx->queue->elevator->elevator_data;

    //有req要处理时，返回1
	return !list_empty_careful(&dd->dispatch) ||
		!list_empty_careful(&dd->fifo_list[0]) ||
		!list_empty_careful(&dd->fifo_list[1]);
}

/*
 * sysfs parts below
 */
static ssize_t
deadline_var_show(int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static ssize_t
deadline_var_store(int *var, const char *page, size_t count)
{
	char *p = (char *) page;

	*var = simple_strtol(p, &p, 10);
	return count;
}

#define SHOW_FUNCTION(__FUNC, __VAR, __CONV)				\
static ssize_t __FUNC(struct elevator_queue *e, char *page)		\
{									\
	struct deadline_data *dd = e->elevator_data;			\
	int __data = __VAR;						\
	if (__CONV)							\
		__data = jiffies_to_msecs(__data);			\
	return deadline_var_show(__data, (page));			\
}
SHOW_FUNCTION(deadline_read_expire_show, dd->fifo_expire[READ], 1);
SHOW_FUNCTION(deadline_write_expire_show, dd->fifo_expire[WRITE], 1);
SHOW_FUNCTION(deadline_writes_starved_show, dd->writes_starved, 0);
SHOW_FUNCTION(deadline_front_merges_show, dd->front_merges, 0);
SHOW_FUNCTION(deadline_fifo_batch_show, dd->fifo_batch, 0);
#undef SHOW_FUNCTION

#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	struct deadline_data *dd = e->elevator_data;			\
	int __data;							\
	int ret = deadline_var_store(&__data, (page), count);		\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	if (__CONV)							\
		*(__PTR) = msecs_to_jiffies(__data);			\
	else								\
		*(__PTR) = __data;					\
	return ret;							\
}
STORE_FUNCTION(deadline_read_expire_store, &dd->fifo_expire[READ], 0, INT_MAX, 1);
STORE_FUNCTION(deadline_write_expire_store, &dd->fifo_expire[WRITE], 0, INT_MAX, 1);
STORE_FUNCTION(deadline_writes_starved_store, &dd->writes_starved, INT_MIN, INT_MAX, 0);
STORE_FUNCTION(deadline_front_merges_store, &dd->front_merges, 0, 1, 0);
STORE_FUNCTION(deadline_fifo_batch_store, &dd->fifo_batch, 0, INT_MAX, 0);
#undef STORE_FUNCTION

#define DD_ATTR(name) \
	__ATTR(name, S_IRUGO|S_IWUSR, deadline_##name##_show, \
				      deadline_##name##_store)

static struct elv_fs_entry deadline_attrs[] = {
	DD_ATTR(read_expire),
	DD_ATTR(write_expire),
	DD_ATTR(writes_starved),
	DD_ATTR(front_merges),
	DD_ATTR(fifo_batch),
	__ATTR_NULL
};

#ifdef CONFIG_BLK_DEBUG_FS
#define DEADLINE_DEBUGFS_DDIR_ATTRS(ddir, name)				\
static void *deadline_##name##_fifo_start(struct seq_file *m,		\
					  loff_t *pos)			\
	__acquires(&dd->lock)						\
{									\
	struct request_queue *q = m->private;				\
	struct deadline_data *dd = q->elevator->elevator_data;		\
									\
	spin_lock(&dd->lock);						\
	return seq_list_start(&dd->fifo_list[ddir], *pos);		\
}									\
									\
static void *deadline_##name##_fifo_next(struct seq_file *m, void *v,	\
					 loff_t *pos)			\
{									\
	struct request_queue *q = m->private;				\
	struct deadline_data *dd = q->elevator->elevator_data;		\
									\
	return seq_list_next(v, &dd->fifo_list[ddir], pos);		\
}									\
									\
static void deadline_##name##_fifo_stop(struct seq_file *m, void *v)	\
	__releases(&dd->lock)						\
{									\
	struct request_queue *q = m->private;				\
	struct deadline_data *dd = q->elevator->elevator_data;		\
									\
	spin_unlock(&dd->lock);						\
}									\
									\
static const struct seq_operations deadline_##name##_fifo_seq_ops = {	\
	.start	= deadline_##name##_fifo_start,				\
	.next	= deadline_##name##_fifo_next,				\
	.stop	= deadline_##name##_fifo_stop,				\
	.show	= blk_mq_debugfs_rq_show,				\
};									\
									\
static int deadline_##name##_next_rq_show(void *data,			\
					  struct seq_file *m)		\
{									\
	struct request_queue *q = data;					\
	struct deadline_data *dd = q->elevator->elevator_data;		\
	struct request *rq = dd->next_rq[ddir];				\
									\
	if (rq)								\
		__blk_mq_debugfs_rq_show(m, rq);			\
	return 0;							\
}
DEADLINE_DEBUGFS_DDIR_ATTRS(READ, read)
DEADLINE_DEBUGFS_DDIR_ATTRS(WRITE, write)
#undef DEADLINE_DEBUGFS_DDIR_ATTRS

static int deadline_batching_show(void *data, struct seq_file *m)
{
	struct request_queue *q = data;
	struct deadline_data *dd = q->elevator->elevator_data;

	seq_printf(m, "%u\n", dd->batching);
	return 0;
}

static int deadline_starved_show(void *data, struct seq_file *m)
{
	struct request_queue *q = data;
	struct deadline_data *dd = q->elevator->elevator_data;

	seq_printf(m, "%u\n", dd->starved);
	return 0;
}

static void *deadline_dispatch_start(struct seq_file *m, loff_t *pos)
	__acquires(&dd->lock)
{
	struct request_queue *q = m->private;
	struct deadline_data *dd = q->elevator->elevator_data;

	spin_lock(&dd->lock);
	return seq_list_start(&dd->dispatch, *pos);
}

static void *deadline_dispatch_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct request_queue *q = m->private;
	struct deadline_data *dd = q->elevator->elevator_data;

	return seq_list_next(v, &dd->dispatch, pos);
}

static void deadline_dispatch_stop(struct seq_file *m, void *v)
	__releases(&dd->lock)
{
	struct request_queue *q = m->private;
	struct deadline_data *dd = q->elevator->elevator_data;

	spin_unlock(&dd->lock);
}

static const struct seq_operations deadline_dispatch_seq_ops = {
	.start	= deadline_dispatch_start,
	.next	= deadline_dispatch_next,
	.stop	= deadline_dispatch_stop,
	.show	= blk_mq_debugfs_rq_show,
};

#define DEADLINE_QUEUE_DDIR_ATTRS(name)						\
	{#name "_fifo_list", 0400, .seq_ops = &deadline_##name##_fifo_seq_ops},	\
	{#name "_next_rq", 0400, deadline_##name##_next_rq_show}
static const struct blk_mq_debugfs_attr deadline_queue_debugfs_attrs[] = {
	DEADLINE_QUEUE_DDIR_ATTRS(read),
	DEADLINE_QUEUE_DDIR_ATTRS(write),
	{"batching", 0400, deadline_batching_show},
	{"starved", 0400, deadline_starved_show},
	{"dispatch", 0400, .seq_ops = &deadline_dispatch_seq_ops},
	{},
};
#undef DEADLINE_QUEUE_DDIR_ATTRS
#endif

static struct elevator_mq_ops dd_ops = {
	.insert_requests	= dd_insert_requests,
	.dispatch_request	= dd_dispatch_request,
	.next_request		= elv_rb_latter_request,
	.former_request		= elv_rb_former_request,
	.bio_merge		= dd_bio_merge,//合并
	.request_merge		= dd_request_merge,
	.requests_merged	= dd_merged_requests,
	.request_merged		= dd_request_merged,
	.has_work		= dd_has_work,
	.init_sched		= dd_init_queue,
	.exit_sched		= dd_exit_queue,
};

static struct elevator_type mq_deadline = {
	.elevator_attrs = deadline_attrs,
	.elevator_name = "mq-deadline",
	.elevator_owner = THIS_MODULE,
};
MODULE_ALIAS("mq-deadline-iosched");

static int __init deadline_init(void)
{
	int ret = elv_register(&mq_deadline);
	struct elevator_type_aux *aux;

	if (ret)
		return ret;

	aux = elevator_aux_find(&mq_deadline);
	memcpy(&aux->ops.mq, &dd_ops, sizeof(struct elevator_mq_ops));
	aux->uses_mq = true;
	aux->elevator_alias = "deadline",
	aux->queue_debugfs_attrs = deadline_queue_debugfs_attrs;

	return 0;
}

static void __exit deadline_exit(void)
{
	elv_unregister(&mq_deadline);
}

module_init(deadline_init);
module_exit(deadline_exit);

MODULE_AUTHOR("Jens Axboe");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MQ deadline IO scheduler");
