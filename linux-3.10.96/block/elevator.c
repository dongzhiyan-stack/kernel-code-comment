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

static DEFINE_SPINLOCK(elv_list_lock);
static LIST_HEAD(elv_list);

/*
 * Merge hash stuff.
 */
//hash key是req的扇区结束地址呀
#define rq_hash_key(rq)		(blk_rq_pos(rq) + blk_rq_sectors(rq))

/*
 * Query io scheduler to see if the current process issuing bio may be
 * merged with rq.
 */
static int elv_iosched_allow_merge(struct request *rq, struct bio *bio)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (e->type->ops.elevator_allow_merge_fn)
		return e->type->ops.elevator_allow_merge_fn(q, rq, bio);

	return 1;
}

/*
 * can we safely merge with this request?
 */
bool elv_rq_merge_ok(struct request *rq, struct bio *bio)
{
    //对本次新的bio能否合并到rq做各个前期检查，检查通过返回true
	if (!blk_rq_merge_ok(rq, bio))
		return 0;

	if (!elv_iosched_allow_merge(rq, bio))
		return 0;

	return 1;
}
EXPORT_SYMBOL(elv_rq_merge_ok);

static struct elevator_type *elevator_find(const char *name)
{
	struct elevator_type *e;

	list_for_each_entry(e, &elv_list, list) {
		if (!strcmp(e->elevator_name, name))
			return e;
	}

	return NULL;
}

static void elevator_put(struct elevator_type *e)
{
	module_put(e->elevator_owner);
}

static struct elevator_type *elevator_get(const char *name, bool try_loading)
{
	struct elevator_type *e;

	spin_lock(&elv_list_lock);

	e = elevator_find(name);
	if (!e && try_loading) {
		spin_unlock(&elv_list_lock);
		request_module("%s-iosched", name);
		spin_lock(&elv_list_lock);
		e = elevator_find(name);
	}

	if (e && !try_module_get(e->elevator_owner))
		e = NULL;

	spin_unlock(&elv_list_lock);

	return e;
}

static char chosen_elevator[ELV_NAME_MAX];

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

	spin_lock(&elv_list_lock);
	e = elevator_find(chosen_elevator);
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
	kobject_init(&eq->kobj, &elv_ktype);
	mutex_init(&eq->sysfs_lock);
	hash_init(eq->hash);

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
		e = elevator_get(name, true);
		if (!e)
			return -EINVAL;
	}

	/*
	 * Use the default elevator specified by config boot param or
	 * config option.  Don't try to load modules as we could be running
	 * off async and request_module() isn't allowed from async.
	 */
	if (!e && *chosen_elevator) {
		e = elevator_get(chosen_elevator, false);
		if (!e)
			printk(KERN_ERR "I/O scheduler %s not found\n",
							chosen_elevator);
	}

	if (!e) {
		e = elevator_get(CONFIG_DEFAULT_IOSCHED, false);
		if (!e) {
			printk(KERN_ERR
				"Default I/O scheduler not found. " \
				"Using noop.\n");
			e = elevator_get("noop", false);
		}
	}

	err = e->ops.elevator_init_fn(q, e);
	return 0;
}
EXPORT_SYMBOL(elevator_init);

void elevator_exit(struct elevator_queue *e)
{
	mutex_lock(&e->sysfs_lock);
	if (e->type->ops.elevator_exit_fn)
		e->type->ops.elevator_exit_fn(e);
	mutex_unlock(&e->sysfs_lock);

	kobject_put(&e->kobj);
}
EXPORT_SYMBOL(elevator_exit);

static inline void __elv_rqhash_del(struct request *rq)
{
	hash_del(&rq->hash);
}

static void elv_rqhash_del(struct request_queue *q, struct request *rq)
{
	if (ELV_ON_HASH(rq))
		__elv_rqhash_del(rq);
}

static void elv_rqhash_add(struct request_queue *q, struct request *rq)
{
    //e就是IO调度算法实体
	struct elevator_queue *e = q->elevator;

	BUG_ON(ELV_ON_HASH(rq));
    //req根据扇区结束地址rq_hash_key(rq)添加到IO调度算法的hash链表里，做hash索引是为了在IO算法队列里搜索可以合并的req时，提高搜索速度
	hash_add(e->hash, &rq->hash, rq_hash_key(rq));
}

static void elv_rqhash_reposition(struct request_queue *q, struct request *rq)
{
    //删除req
	__elv_rqhash_del(rq);
    //再添加req，应该是req有了新的合并，所以要重新排序req吧
	elv_rqhash_add(q, rq);
}
//遍历hash队列的req，如果这个req的扇区结束地址等于新的req(或者bio)的扇区起始地址，说明新的req(或者bio)可以后项合并到这个hash队列的req
//调用路径是:elv_merge->elv_rqhash_find 和 elv_attempt_insert_merge->elv_rqhash_find
static struct request *elv_rqhash_find(struct request_queue *q, sector_t offset)//offset新的req(或者bio)的扇区起始地址
{
	struct elevator_queue *e = q->elevator;
	struct hlist_node *next;
	struct request *rq;

    //新的req靠这个hash添加到IO调度算法的hash链表e->hash里，做hash索引是为了在IO算法队列里搜索可以合并的req时，提高搜索速度
    //这里遍历hash链表上的req
	hash_for_each_possible_safe(e->hash, rq, next, hash, offset) {
		BUG_ON(!ELV_ON_HASH(rq));

		if (unlikely(!rq_mergeable(rq))) {
			__elv_rqhash_del(rq);
			continue;
		}
        //rq_hash_key(rq)是本次搜索到的hash队列的req的扇区结束地址，offset是本次新的req的扇区起始地址，二者相等说明新的req可以后项合并
        //到这个hash队列req。req是以扇区起始地址作为hash key加入hash队列的!
		if (rq_hash_key(rq) == offset)
			return rq;
	}

	return NULL;
}

/*
 * RB-tree support functions for inserting/lookup/removal of requests
 * in a sorted RB tree.
 */
//按照req的磁盘起始地址把req添加到红黑树队列里，这个红黑树里req的排列规则是，谁的磁盘起始地址小谁靠左
void elv_rb_add(struct rb_root *root, struct request *rq)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct request *__rq;

	while (*p) {
		parent = *p;
        //取出红黑树中的__rq
		__rq = rb_entry(parent, struct request, rb_node);
        //rq的磁盘起始地址比__rq的小，那rq应该插入到左子树，显然，谁的磁盘起始地址小，谁靠左
		if (blk_rq_pos(rq) < blk_rq_pos(__rq))
			p = &(*p)->rb_left;
        //否则，rq的磁盘起始地址>=__rq的，则rq应该插入到右子树
		else if (blk_rq_pos(rq) >= blk_rq_pos(__rq))
			p = &(*p)->rb_right;
	}
    //rq链接到红黑树
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


//在调度算法的红黑树队列里遍历req,如果该req起始扇区地址等于bio的扇区结束地址则返回该req，否则返回NULL

//struct rb_root *root调度队列保存req的红黑树头结点吧，有两个，一个读，一个写。红黑树队列中的req排序的规则是req的磁盘起始扇区，
//可以认为是按照磁盘起始扇区从小到大排列的吧。
struct request *elv_rb_find(struct rb_root *root, sector_t sector)//sector是bio_end_sector(bio)，即bio磁盘扇区的结束地址
{
	struct rb_node *n = root->rb_node;
	struct request *rq;

	while (n) {
        //从root根节点开始遍历，依次取出红黑树中的一个req
		rq = rb_entry(n, struct request, rb_node);
        //bio的扇区结束地址sector 小于 req的起始扇区地址，则遍历左子树，很明显，红黑树队列的req排列规则是，谁的起始扇区地址小谁靠左
		if (sector < blk_rq_pos(rq))
			n = n->rb_left;//这里可能是n = n->rb_left=NULL则说明没有找到匹配的req
        //bio的扇区结束地址sector 大于  req的起始扇区地址，则遍历右子树
		else if (sector > blk_rq_pos(rq))
			n = n->rb_right;//这里可能是n = n->rb_right=NULL则说明没有找到匹配的req
		else//我去，这是bio的扇区结束地址sector = req的起始扇区地址呀，所示要把bio合并到req前边，这是前项合并
			return rq;
	}
    //如果走到这里，应该是红黑树队列就没有req成员吧，是空的，因为只要红黑树有一个req,那bio的磁盘结束地址，肯定 大于或小于或等于 req的起始地址吧
    //错了错了，只有sector = blk_rq_pos(rq)才会return rq，如果没有找到匹配的req,n = n->rb_right/rb_left遍历到树底，n为NULL退出循环
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
//把req添加到rq的queue_head队列，将来磁盘驱动程序就是从queue_head链表取出req传输的
void elv_dispatch_add_tail(struct request_queue *q, struct request *rq)
{
	if (q->last_merge == rq)
		q->last_merge = NULL;
    //req从hash队列剔除
	elv_rqhash_del(q, rq);
    //
	q->nr_sorted--;
    //结束扇区
	q->end_sector = rq_end_sector(rq);
	q->boundary_rq = rq;
    //把req添加到rq的queue_head队列，将来磁盘驱动程序就是从queue_head链表取出req传输的
	list_add_tail(&rq->queuelist, &q->queue_head);
}
EXPORT_SYMBOL(elv_dispatch_add_tail);

//在elv调度器里查找是否有可以合并的req，找到则可以bio后项或前项合并到req。这个是调用具体的IO调度算法函数寻找可以合并的req。
//函数返回值 ELEVATOR_BACK_MERGE(前项合并的req)、ELEVATOR_FRONT_MERGE(前项合并)、ELEVATOR_NO_MERGE(没有找到可以合并的req)

//尝试3次合并:1 bio能否前项或者后项合并到q->last_merge;2 bio能否后项合并到hash队列的req;3:bio能否前项合并到deadline调度
//算法红黑树队列的req，返回值ELEVATOR_BACK_MERGE或ELEVATOR_FRONT_MERGE。如果三者都不能合并只有返回ELEVATOR_NO_MERGE。
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
	//是否可以把bio合并到q->last_merge，上次rq队列合并过的rq，elv_rq_merge_ok是做一些权限检查啥的
	if (q->last_merge && elv_rq_merge_ok(q->last_merge, bio)) {
        //检查bio和q->last_merge代表的req磁盘范围是否挨着，挨着则可以合并bio到q->last_merge，分为前项合并和后项合并
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
	 //新加入IO调度队列的req会做hash索引，这应该是是根据bio的扇区起始地址在hash表找匹配的req吧，
	 
	 //遍历hash队列req，如果该req的扇区结束地址等于bio的扇区起始地址，bio可以后项合并到req
	__rq = elv_rqhash_find(q, bio->bi_sector);
	if (__rq && elv_rq_merge_ok(__rq, bio)) {
		*req = __rq;
		return ELEVATOR_BACK_MERGE;//找到可以合并的req，这里返回ELEVATOR_BACK_MERGE，表示后项合并
	}

    //具体IO调度算法函数cfq_merge或者deadline_merge，找到可以合并的bio的req，这里是把bio前项合并到req
	if (e->type->ops.elevator_merge_fn)
        //deadline是在红黑树队列里遍历req,如果该req起始扇区地址等于bio的扇区结束地址，返回前项合并(bio合并到req的前边)
        //req是个双重指针，保存这个红黑树队列里匹配到的req
		return e->type->ops.elevator_merge_fn(q, req, bio);//deadline_merge，这里返回ELEVATOR_FRONT_MERGE，前项合并
/*
    // 这是是3.10.0.957.27内核，就增加了e->aux->ops.mq.request_merge
    if (e->uses_mq && e->aux->ops.mq.request_merge)
       //dd_request_merge 和 deadline_merge的函数源码就是一样的，就是在调度算法的 读或写红黑树队列里，找到等于bio_end_sector(bio)的req
       //找到说明bio的扇区结束地址等于req的扇区起始地址，则返回前项合并ELEVATOR_FRONT_MERGE
          return e->aux->ops.mq.request_merge(q, req, bio);//dd_request_merge
    else if (!e->uses_mq && e->aux->ops.sq.elevator_merge_fn)
    //具体IO调度算法函数cfq_merge或者deadline_merge，该函数是在调度算法的 读或写红黑树队列里，遍历req,找到req起始扇区地址
    //等于bio_end_sector(bio)的req，如果找到匹配的req，说明bio的扇区结束地址等于req的扇区起始地址，则返回前项合并ELEVATOR_FRONT_MERGE
          return e->aux->ops.sq.elevator_merge_fn(q, req, bio);
*/

	return ELEVATOR_NO_MERGE;
}

/*
 * Attempt to do an insertion back merge. Only check for the case where
 * we can append 'rq' to an existing request, so we can throw 'rq' away
 * afterwards.
 *
 * Returns true if we merged, false otherwise
 */
//首先尝试将rq后项合并到q->last_merge，再尝试将rq后项合并到hash队列的某一个__rq，合并规则是rq的扇区起始地址等于q->last_merge或__rq
//的扇区结束地址，都是调用blk_attempt_req_merge()进行合并。并更新IO使用率等数据,更新合并后的req在hash队列中的位置。如果使用了
//deadline调度算法，还会从fifo队列剔除掉rq，更新dd->next_rq[]赋值rq的下一个req。
static bool elv_attempt_insert_merge(struct request_queue *q,
				     struct request *rq)
{
	struct request *__rq;
	bool ret;

	if (blk_queue_nomerges(q))
		return false;

	/*
	 * First try one-hit cache.
	 */
//尝试把req合并到q->last_merge后边，并更新IO使用率数据。然后调用IO调度算法的elevator_merge_req_fn回调函数，
//当为deadline调度算法时，执行过程是:rq已经合并到了q->last_merge后,在fifo队列里，把q->last_merge移动到rq节点的位置，
//更新q->last_merge的超时时间。从fifo队列和红黑树剔除rq,还更新dd->next_rq[]赋值rq的下一个req。
//因为q->last_merge合并了rq，扇区结束地址变大了，则q->last_merge从hash队列中删除掉再重新按照扇区结束地址在hash队列中排序。
	if (q->last_merge && blk_attempt_req_merge(q, q->last_merge, rq))
		return true;//合并成功这里直接返回

	if (blk_queue_noxmerges(q))
		return false;

	ret = false;
	/*
	 * See if our hash lookup can find a potential backmerge.
	 */
	while (1) {
        //遍历hash队列的req(即__rq)，如果这个__rq的扇区结束地址等于本次新的req(即rq)的扇区起始地址，说明新的req可以后项合并到
        //这个hash队列的req
		__rq = elv_rqhash_find(q, blk_rq_pos(rq));//blk_rq_pos(rq)是req的扇区起始地址
        //这里也是执行blk_attempt_req_merge将本次新的req(即rq)后项合并到hash队列的req(即__rq),合并失败直接break返回，合并成功的话
        //则在hash队列里搜索有哪个req能否合并__rq。此时的__rq扇区结束地址增大，但扇区起始地址没变，不能后项合并到hash队列的其他req吧?
        //有合并的意义吗?也许hash队列的req并不是全部合并过的??????
		if (!__rq || !blk_attempt_req_merge(q, __rq, rq))
			break;

		/* The merged request could be merged with others, try again */
		ret = true;
		rq = __rq;
	}

	return ret;
}
//req发生了前项或者后项合并，req的扇区起始或者结束地址增大，需要把req从调度算法deadline红黑树队列或者hash队列中剔除，
//再按照req新的扇区起始或者结束地址插入队列
void elv_merged_request(struct request_queue *q, struct request *rq, int type)
{
	struct elevator_queue *e = q->elevator;

	/*貌似deadline调度算法的红黑树，在插入req时，就是按照req代表的扇区起始地址来对比，谁的扇区起始地址小，谁排列靠左.
	  见 deadline_add_request->deadline_add_rq_rb->elv_rb_add插入req和elv_merge->deadline_merge->elv_rb_find遍历req。
	  blk_mq_sched_try_merge->elv_merged_request->deadline_merged_request重新req排序，针对deadline调度算法的红黑树队列，
	  对前项合并后的req进行重新排序，因为前项合并后的req扇区起始地址变小了，既然红黑树队列对req排序规则是谁的扇区起始地址小谁靠左,
	  那就要对这个req重新再红黑树队列里排序。
	  
	  同样的，deadline调度算法的hash队列，也是一种req队列。错了，hash队列不是deadline算法的，是默认的elv调度算法的IO队列。一直有个
	  认知错误，如果不设置deadline调度算法，难道就没有调度算法队列吗?错了，即便不设置deadline也有默认的elv调度算法hash队列。
	  hash队列的req排序规则是req的扇区结束地址，为什么这么说，
	  看hash添加时的elv_rqhash_add函数里的hash_add(e->hash, &rq->hash, rq_hash_key(rq))，rq_hash_key(rq)就是hash key，req扇区结束地址。
	  所以在elv_merged_request->elv_rqhash_reposition中，是req进行了后项合并，扇区结束地址变大了，那就要对这个req进行在hash表中冲洗排序。
	  blk_queue_bio->add_acct_request->__elv_add_request->elv_rqhash_add添加，elv_merge->elv_rqhash_find遍历
	  blk_mq_sched_try_merge->elv_merged_request->elv_rqhash_reposition重新排序。对后项合并后的req进行一次重新排序
	*/

    //刚req发生了前项合并，req扇区起始地址增大，把req从deadline的红黑树队列删除再按照新的扇区起始地址插入红黑树队列
	if (e->type->ops.elevator_merged_fn)//cfq_merged_request和deadline_merged_request，mq没有
		e->type->ops.elevator_merged_fn(q, rq, type);

	if (type == ELEVATOR_BACK_MERGE)
        //刚req发生了后项合并，req扇区结束地址增大，把req从hash队列删除再按照新的扇区结束地址插入hash队列
		elv_rqhash_reposition(q, rq);

    //q->last_merge保存刚发生合并的req
	q->last_merge = rq;
}
//在这里，next已经合并到了rq,在fifo队列里，把req移动到next节点的位置，更新req的超时时间。从fifo队列和红黑树剔除next,
//还更新dd->next_rq[]赋值next的下一个req。因为rq合并了next，扇区结束地址变大了，则rq从hash队列中删除掉再重新再hash中排序
void elv_merge_requests(struct request_queue *q, struct request *rq,
			     struct request *next)//rq是合并母体，比如q->last_merge或hash队列的req，next是本次新的req
{
	struct elevator_queue *e = q->elevator;
	const int next_sorted = next->cmd_flags & REQ_SORTED;

    //在fifo队列里，把req移动到next节点的位置，更新req的超时时间。从fifo队列和红黑树剔除next,还更新dd->next_rq[]赋值next的下一个req
	if (next_sorted && e->type->ops.elevator_merge_req_fn)
		e->type->ops.elevator_merge_req_fn(q, rq, next);//deadline_merged_requests 或noop_merged_requests或cfq_merged_requests
/*
    //3.10.0.957.27内核新增的，添加针对的mq-deadline的
    //在fifo队列里，把req移动到next节点的位置，更新req的超时时间。从fifo队列和红黑树剔除next,还更新dd->next_rq[]赋值next的下一个req
    if (e->uses_mq && e->aux->ops.mq.requests_merged)
		e->aux->ops.mq.requests_merged(q, rq, next);//dd_merged_requests，它的原理跟deadline_merged_requests函数很接近
*/		

    //req扇区后边吞并了next，扇区结束地址增大，把req从扇区hash队列删除，再按照新的扇区结束地址加入hash队列
	elv_rqhash_reposition(q, rq);

	if (next_sorted) {
        //把next从hash队列剔除
		elv_rqhash_del(q, next);
        //elv队列req个数减1，实际上就是elv hash队列的req个数减1
		q->nr_sorted--;
	}
    //q->last_merge指向合并后的req
	q->last_merge = rq;
}

void elv_bio_merged(struct request_queue *q, struct request *rq,
			struct bio *bio)
{
	struct elevator_queue *e = q->elevator;
    //只是增加一部分统计数据吧 
	if (e->type->ops.elevator_bio_merged_fn)
		e->type->ops.elevator_bio_merged_fn(q, rq, bio);
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
	static int printed;

	lockdep_assert_held(q->queue_lock);
//选择合适待派发给驱动传输的req,然后把req添加到rq的queue_head队列，设置新的next_rq，并把req从fifo队列和红黑树队列剔除，
//将来磁盘驱动程序就是从queue_head链表取出req传输的这个合适的req，这个req的来源有:
//1:上次派发设置的next_rq; 2:read req派发过多而选择的write req; 3:fifo 队列上超时要传输的req，前后兼顾，有固定策略
	while (q->elevator->type->ops.elevator_dispatch_fn(q, 1))//deadline_dispatch_requests
		;
	if (q->nr_sorted && printed++ < 10) {
		printk(KERN_ERR "%s: forced dispatching is broken "
		       "(nr_sorted=%u), please report this\n",
		       q->elevator->type->elevator_name, q->nr_sorted);
	}
}
//新分配的req插入IO算法队列，或者是把当前进程plug链表上req全部插入到IO调度算法队列
void __elv_add_request(struct request_queue *q, struct request *rq, int where)
{//blk_flush_plug_list调用时，req有(REQ_FLUSH | REQ_FUA)和属性，则是where是ELEVATOR_INSERT_FLUSH，否则是ELEVATOR_INSERT_SORT_MERGE
//blk_queue_bio单独提交IO是ELEVATOR_INSERT_SORT
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
	case ELEVATOR_INSERT_FRONT://前向合并
		rq->cmd_flags |= REQ_SOFTBARRIER;
		list_add(&rq->queuelist, &q->queue_head);//req直接插入q->queue_head队列头而已，并没有进行req合并
		break;

	case ELEVATOR_INSERT_BACK://后向合并
		rq->cmd_flags |= REQ_SOFTBARRIER;
        //循环调用deadline算法的elevator_dispatch_fn接口一直选择派发的req直到队列
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
		//这里调用底层驱动数据传输函数，就会从rq的queue_head队列取出req发送给磁盘驱动去传输
		__blk_run_queue(q);
		break;

	case ELEVATOR_INSERT_SORT_MERGE://把进程独有的plug链表上的req插入IO调度算法队列里走这里
		/*
		 * If we succeed in merging this request with one in the
		 * queue already, we are done - rq has now been freed,
		 * so no need to do anything further.
		 */
		if (elv_attempt_insert_merge(q, rq))//把
			break;
	case ELEVATOR_INSERT_SORT://新分配的req插入的IO调度算法队列走这里
		BUG_ON(rq->cmd_type != REQ_TYPE_FS);
		rq->cmd_flags |= REQ_SORTED;
        //队列插入新的一个req
		q->nr_sorted++;
		if (rq_mergeable(rq)) {
            //新的req靠rq->hash添加到IO调度算法的hash链表里
			elv_rqhash_add(q, rq);
			if (!q->last_merge)
				q->last_merge = rq;
		}

		/*
		 * Some ioscheds (cfq) run q->request_fn directly, so
		 * rq cannot be accessed after calling
		 * elevator_add_req_fn.
		 */
		//把req插入到IO调度算法队列里，deadline是插入到红黑树队列和fifo队列
		//mq-deadline没有这个函数,还有没有IO调度算法的场景是noop_add_request函数
		q->elevator->type->ops.elevator_add_req_fn(q, rq);//deadline_add_request/noop_add_request
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
//只是从IO调度算法队列里取出rq的下一个rq吧,不同的调度算法调度队列不一样
struct request *elv_latter_request(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (e->type->ops.elevator_latter_req_fn)//elv_rb_latter_request和noop_latter_request
		return e->type->ops.elevator_latter_req_fn(q, rq);
	return NULL;
}

struct request *elv_former_request(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;
    //elv_rb_former_request和noop_former_request
	if (e->type->ops.elevator_former_req_fn)
		return e->type->ops.elevator_former_req_fn(q, rq);
	return NULL;
}

int elv_set_request(struct request_queue *q, struct request *rq,
		    struct bio *bio, gfp_t gfp_mask)
{
	struct elevator_queue *e = q->elevator;

	if (e->type->ops.elevator_set_req_fn)
		return e->type->ops.elevator_set_req_fn(q, rq, bio, gfp_mask);
	return 0;
}

void elv_put_request(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (e->type->ops.elevator_put_req_fn)
		e->type->ops.elevator_put_req_fn(rq);
}

int elv_may_queue(struct request_queue *q, int rw)
{
	struct elevator_queue *e = q->elevator;

	if (e->type->ops.elevator_may_queue_fn)
		return e->type->ops.elevator_may_queue_fn(q, rw);

	return ELV_MQUEUE_MAY;
}

void elv_abort_queue(struct request_queue *q)
{
	struct request *rq;

	blk_abort_flushes(q);

	while (!list_empty(&q->queue_head)) {
		rq = list_entry_rq(q->queue_head.next);
		rq->cmd_flags |= REQ_QUIET;
		trace_block_rq_abort(q, rq);
		/*
		 * Mark this request as started so we don't trigger
		 * any debug logic in the end I/O path.
		 */
		blk_start_request(rq);
		__blk_end_request_all(rq, -EIO);
	}
}
EXPORT_SYMBOL(elv_abort_queue);

void elv_completed_request(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	/*
	 * request is released from the driver, io must be done
	 */
	if (blk_account_rq(rq)) {
		q->in_flight[rq_is_sync(rq)]--;
		if ((rq->cmd_flags & REQ_SORTED) &&
		    e->type->ops.elevator_completed_req_fn)
			e->type->ops.elevator_completed_req_fn(q, rq);
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

	/* register, don't allow duplicate names */
	spin_lock(&elv_list_lock);
	if (elevator_find(e->elevator_name)) {
		spin_unlock(&elv_list_lock);
		if (e->icq_cache)
			kmem_cache_destroy(e->icq_cache);
		return -EBUSY;
	}
	list_add_tail(&e->list, &elv_list);
	spin_unlock(&elv_list_lock);

	/* print pretty message */
	if (!strcmp(e->elevator_name, chosen_elevator) ||
			(!*chosen_elevator &&
			 !strcmp(e->elevator_name, CONFIG_DEFAULT_IOSCHED)))
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
}
EXPORT_SYMBOL_GPL(elv_unregister);

/*
 * switch to new_e io scheduler. be careful not to introduce deadlocks -
 * we don't free the old io scheduler, before we have allocated what we
 * need for the new one. this way we have a chance of going back to the old
 * one, if the new one fails init for some reason.
 */
static int elevator_switch(struct request_queue *q, struct elevator_type *new_e)
{
	struct elevator_queue *old = q->elevator;
	bool registered = old->registered;
	int err;

	/*
	 * Turn on BYPASS and drain all requests w/ elevator private data.
	 * Block layer doesn't call into a quiesced elevator - all requests
	 * are directly put on the dispatch list without elevator data
	 * using INSERT_BACK.  All requests have SOFTBARRIER set and no
	 * merge happens either.
	 */
	blk_queue_bypass_start(q);

	/* unregister and clear all auxiliary data of the old elevator */
	if (registered)
		elv_unregister_queue(q);

	spin_lock_irq(q->queue_lock);
	ioc_clear_queue(q);
	spin_unlock_irq(q->queue_lock);

	/* allocate, init and register new elevator */
	err = new_e->ops.elevator_init_fn(q, new_e);
	if (err)
		goto fail_init;

	if (registered) {
		err = elv_register_queue(q);
		if (err)
			goto fail_register;
	}

	/* done, kill the old one and finish */
	elevator_exit(old);
	blk_queue_bypass_end(q);

	blk_add_trace_msg(q, "elv switch: %s", new_e->elevator_name);

	return 0;

fail_register:
	elevator_exit(q->elevator);
fail_init:
	/* switch failed, restore and re-register old elevator */
	q->elevator = old;
	elv_register_queue(q);
	blk_queue_bypass_end(q);

	return err;
}

/*
 * Switch this queue to the given IO scheduler.
 */
static int __elevator_change(struct request_queue *q, const char *name)
{
	char elevator_name[ELV_NAME_MAX];
	struct elevator_type *e;

	if (!q->elevator)
		return -ENXIO;

	strlcpy(elevator_name, name, sizeof(elevator_name));
	e = elevator_get(strstrip(elevator_name), true);
	if (!e) {
		printk(KERN_ERR "elevator: type %s not found\n", elevator_name);
		return -EINVAL;
	}

	if (!strcmp(elevator_name, q->elevator->type->elevator_name)) {
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

	if (!q->elevator)
		return count;

	ret = __elevator_change(q, name);
	if (!ret)
		return count;

	printk(KERN_ERR "elevator: switch to %s failed\n", name);
	return ret;
}

ssize_t elv_iosched_show(struct request_queue *q, char *name)
{
	struct elevator_queue *e = q->elevator;
	struct elevator_type *elv;
	struct elevator_type *__e;
	int len = 0;

	if (!q->elevator || !blk_queue_stackable(q))
		return sprintf(name, "none\n");

	elv = e->type;

	spin_lock(&elv_list_lock);
	list_for_each_entry(__e, &elv_list, list) {
		if (!strcmp(elv->elevator_name, __e->elevator_name))
			len += sprintf(name+len, "[%s] ", elv->elevator_name);
		else
			len += sprintf(name+len, "%s ", __e->elevator_name);
	}
	spin_unlock(&elv_list_lock);

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
//应该是找到IO调度算法队列里的rq的下一个rq，这个队列貌似只是靠着rq->rb_node构成的一个树形队列呀
struct request *elv_rb_latter_request(struct request_queue *q,
				      struct request *rq)
{
	struct rb_node *rbnext = rb_next(&rq->rb_node);

	if (rbnext)
		return rb_entry_rq(rbnext);

	return NULL;
}
EXPORT_SYMBOL(elv_rb_latter_request);
