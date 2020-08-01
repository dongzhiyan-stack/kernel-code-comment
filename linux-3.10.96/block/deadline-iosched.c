/*
 *  Deadline i/o scheduler.
 *
 *  Copyright (C) 2002 Jens Axboe <axboe@kernel.dk>
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
#include <linux/rbtree.h>

/*
 * See Documentation/block/deadline-iosched.txt
 */
static const int read_expire = HZ / 2;  /* max time before a read is submitted. */
static const int write_expire = 5 * HZ; /* ditto for writes, these limits are SOFT! */
static const int writes_starved = 2;    /* max times reads can starve a write */
static const int fifo_batch = 16;       /* # of sequential requests treated as one
				     by the above parameters. For throughput. */
//IO调度算法结构体dd
struct deadline_data {
	/*
	 * run time data
	 */

	/*
	 * requests (deadline_rq s) are present on both sort_list and fifo_list
	 */
	 /*deadline调度算法的红黑树，在插入req时，就是按照req代表的扇区起始地址来对比，谁的扇区起始地址小，谁排列靠左.
	  见 deadline_add_request->deadline_add_rq_rb->elv_rb_add插入req和elv_merge->deadline_merge->elv_rb_find遍历req。
	  blk_mq_sched_try_merge->elv_merged_request->deadline_merged_request重新req排序，针对deadline调度算法的红黑树队列，
	  对前项合并后的req进行重新排序，因为前项合并后的req扇区起始地址变小了，既然红黑树队列对req排序规则是谁的扇区起始地址小谁靠左,
	  那就要对这个req重新再红黑树队列里排序。
	  
	  同样的，deadline调度算法的hash队列，也是一种req队列，但排序规则是req的扇区结束地址，为什么这么说，
	  看hash添加时的elv_rqhash_add函数里的hash_add(e->hash, &rq->hash, rq_hash_key(rq))，rq_hash_key(rq)就是hash key，req扇区结束地址。
	  所以在elv_merged_request->elv_rqhash_reposition中，是req进行了后项合并，扇区结束地址变大了，那就要对这个req进行在hash表中冲洗排序。
	  blk_queue_bio->add_acct_request->__elv_add_request->elv_rqhash_add添加，elv_merge->elv_rqhash_find遍历
	  blk_mq_sched_try_merge->elv_merged_request->elv_rqhash_reposition重新排序。对后项合并后的req进行一次重新排序
	*/
	
	//deadline调度算法，插入req的红黑树队列的头结点，两个成员分为读和写.红黑树队列中的req排序的规则是req的磁盘起始扇区，
	//可以认为是按照磁盘起始扇区从小到大排列的吧，见deadline_add_request()->deadline_add_rq_rb。
	struct rb_root sort_list[2];
    //deadline调度算法，保存req的fifo队列，两个成员分为读和写,见deadline_add_request()和dd_insert_request，
    //这个队列里的req是按照入队的先后时间排列的
	struct list_head fifo_list[2];

	/*
	 * next in sort order. read, write or both are NULL
	 */
	//每次从红黑树选取一个req发给驱动传输，这个req的下一个req保存在next_rq。
	//elv_merge_requests->dd_merged_requests->deadline_remove_request->deadline_del_rq_rb 中赋值也赋值dd->next_rq[]。
	//下次deadline_dispatch_requests()选择req发给驱动时，直接使用这个next_rq。赋值见deadline_del_rq_rb
	struct request *next_rq[2];
    //如果batching大于等于fifo_batch，不再使用next_rq，否则会一直只向后使用红黑树队列的req向驱动发送传输，队列前边的req得不到发送
    //见deadline_dispatch_requests()
	unsigned int batching;		/* number of sequential requests made */
    //req的磁盘空间end地址,见deadline_move_request()
	sector_t last_sector;		/* head position */
    //见下方的writes_starved，write req得不到选择而饥饿的次数
	unsigned int starved;		/* times reads have starved writes */

	/*
	 * settings that change how the i/o scheduler behaves
	 */
	//deadline设置调度超时时间，超时时间到，则会把fifo队列头的req派发给驱动，见deadline_add_request(),两个成员是读和写
	//deadline_check_fifo()判断fifo队列中req是否有超时的
	int fifo_expire[2];
    //默认是常量16，deadline_dispatch_requests()中向驱动发送req传输时，
	int fifo_batch;
    //deadline_dispatch_requests()中，防止一直选择read req给驱动传输，write req得不到选择而starve饥饿，每次write req得不到选择而饥饿
    //则starved++,writes_starved是饥饿的次数上限，starved大于writes_starved，就强制选择write req
	int writes_starved;
	int front_merges;
};

static void deadline_move_request(struct deadline_data *, struct request *);

static inline struct rb_root *
deadline_rb_root(struct deadline_data *dd, struct request *rq)
{
    //取出调度算法的 读或者写红黑树队列头rb_root
	return &dd->sort_list[rq_data_dir(rq)];
}

/*
 * get the request after `rq' in sector-sorted order
 */
//从红黑树队列中取出req的下一个req
static inline struct request *
deadline_latter_request(struct request *rq)
{
	struct rb_node *node = rb_next(&rq->rb_node);

	if (node)
		return rb_entry_rq(node);

	return NULL;
}
//rq添加到红黑树队列里
static void
deadline_add_rq_rb(struct deadline_data *dd, struct request *rq)
{
	struct rb_root *root = deadline_rb_root(dd, rq);
    //把rq添加到树里，就是按照每个req的起始扇区排序的
	elv_rb_add(root, rq);
}

static inline void
deadline_del_rq_rb(struct deadline_data *dd, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);

	if (dd->next_rq[data_dir] == rq)
		dd->next_rq[data_dir] = deadline_latter_request(rq);

	elv_rb_del(deadline_rb_root(dd, rq), rq);
}

/*
 * add rq to rbtree and fifo
 */
static void
deadline_add_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	const int data_dir = rq_data_dir(rq);
    //rq添加到红黑树队列里
	deadline_add_rq_rb(dd, rq);

	/*
	 * set expire time and add to fifo list
	 */
	//设置req调度超时时间，超时时间到，则会把fifo队列头的req派发给驱动
	rq_set_fifo_time(rq, jiffies + dd->fifo_expire[data_dir]);
    //req插入到fifo队列尾部，入队从队列尾部入队
	list_add_tail(&rq->queuelist, &dd->fifo_list[data_dir]);
}

/*
 * remove rq from rbtree and fifo.
 */
//从fifo队列剔除rq,从红黑树剔除rq。给dd->next_rq[]赋值req的下一个req，下一次从红黑树选择req发给驱动时用到
static void deadline_remove_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;
    //从fifo队列剔除rq
	rq_fifo_clear(rq);
    //给dd->next_rq[]赋值req的下一个req，下一次从红黑树选择req发给驱动时用到。并且把req从红黑树中剔除
	deadline_del_rq_rb(dd, rq);
}

//该函数是在调度算法的 读或写红黑树队列里，遍历req,找到req起始扇区地址等于bio_end_sector(bio)的req，
//如果找到匹配的req，说明bio的扇区结束地址等于req的扇区起始地址，则返回前项合并
static int
deadline_merge(struct request_queue *q, struct request **req, struct bio *bio)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	struct request *__rq;
	int ret;

	/*
	 * check for front merge
	 */
	if (dd->front_merges) {
		sector_t sector = bio_end_sector(bio);
        
         //该函数是在调度算法的 读或写红黑树队列里，遍历req,找到req起始扇区地址等于bio_end_sector(bio)的req返回，否则返回NULL
		__rq = elv_rb_find(&dd->sort_list[bio_data_dir(bio)], sector);
		if (__rq) {
			BUG_ON(sector != blk_rq_pos(__rq));
            //如果找到匹配的req，说明bio的扇区结束地址等于req的扇区起始地址，则返回前项合并
			if (elv_rq_merge_ok(__rq, bio)) {
				ret = ELEVATOR_FRONT_MERGE;
				goto out;
			}
		}
	}

	return ELEVATOR_NO_MERGE;
out:
	*req = __rq;
	return ret;
}

static void deadline_merged_request(struct request_queue *q,
				    struct request *req, int type)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	/*
	 * if the merge was a front merge, we need to reposition request
	 */

    //如果是前项合并，则把要把req从调度算法队列红黑树里剔除掉，重新插入到红黑树。为什么只针对前项合并才对req重排，后项不合并呢?
    if (type == ELEVATOR_FRONT_MERGE) {
		elv_rb_del(deadline_rb_root(dd, req), req);//也是删除req原来位置
		//按照req的磁盘起始地址把req添加到红黑树队列里，这个红黑树里req的排列规则是，谁的磁盘起始地址小谁靠左
		deadline_add_rq_rb(dd, req);
	}
}
//在fifo队列里，把req移动到next节点的位置，更新req的超时时间。从fifo队列和红黑树剔除next,还更新dd->next_rq[]赋值next的下一个req
static void
deadline_merged_requests(struct request_queue *q, struct request *req,
			 struct request *next)
{
	/*
	 * if next expires before rq, assign its expire time to rq
	 * and move into next position (next will be deleted) in fifo
	 */
	//如果next的超时时间早于req，更新到rq超时时间里
	if (!list_empty(&req->queuelist) && !list_empty(&next->queuelist)) {
		if (time_before(rq_fifo_time(next), rq_fifo_time(req))) {
            //在fifo队里，把req移动到next的位置后边
			list_move(&req->queuelist, &next->queuelist);
            //设置req的超时时间
			rq_set_fifo_time(req, rq_fifo_time(next));
		}
	}

	/*
	 * kill knowledge of next, this one is a goner
	 */
	//从fifo队列和红黑树剔除next,还更新dd->next_rq[]赋值next的下一个req
	deadline_remove_request(q, next);
}

/*
 * move request from sort list to dispatch queue.
 */
//把req添加到rq的queue_head队列，并把req从fifo队列和红黑树队列剔除，将来磁盘驱动程序就是从queue_head链表取出req传输的,
static inline void
deadline_move_to_dispatch(struct deadline_data *dd, struct request *rq)
{
	struct request_queue *q = rq->q;
    //从fifo队列和红黑树队列剔除req
	deadline_remove_request(q, rq);
    //把req添加到rq的queue_head队列，将来磁盘驱动程序就是从queue_head链表取出req传输的
	elv_dispatch_add_tail(q, rq);
}

/*
 * move an entry to dispatch queue
 */
//把req添加到rq的queue_head队列，设置新的next_rq，并把req从fifo队列和红黑树队列剔除，将来磁盘驱动程序就是从queue_head链表取出req传输的
static void
deadline_move_request(struct deadline_data *dd, struct request *rq)
{
    //req是read还是write
	const int data_dir = rq_data_dir(rq);

	dd->next_rq[READ] = NULL;
	dd->next_rq[WRITE] = NULL;
    ////从红黑树队列中取出req的下一个req作为next_rq，下次deadline_dispatch_requests选择派发给驱动的req时就可能是它了
	dd->next_rq[data_dir] = deadline_latter_request(rq);
    //req的磁盘空间end地址
	dd->last_sector = rq_end_sector(rq);

	/*
	 * take it off the sort and fifo list, move
	 * to dispatch queue
	 */
	//把req添加到rq的queue_head队列，并把req从fifo队列和红黑树队列剔除，将来磁盘驱动程序就是从queue_head链表取出req传输的,
	deadline_move_to_dispatch(dd, rq);
}

/*
 * deadline_check_fifo returns 0 if there are no expired requests on the fifo,
 * 1 otherwise. Requires !list_empty(&dd->fifo_list[data_dir])
 */
//如果deadline fifo队列有超时的req要传输返回1
static inline int deadline_check_fifo(struct deadline_data *dd, int ddir)
{
    //dd->fifo_list[ddir]应该是fifo队列头，dd->fifo_list[ddir].next是该队列的第一个req,相对最早插入fifo队列尾的req
    //如果这个req超时了，那肯定有超时要传输的req，否则就没有，因为第一个req肯定是最先超时的
	struct request *rq = rq_entry_fifo(dd->fifo_list[ddir].next);

	/*
	 * rq is expired!
	 */
	//rq超时时间到了
	if (time_after_eq(jiffies, rq_fifo_time(rq)))
		return 1;

	return 0;
}

/*
 * deadline_dispatch_requests selects the best request according to
 * read/write expire, fifo_batch, etc
 */
//选的合适待派发给驱动传输的req,然后把req添加到rq的queue_head队列，设置新的next_rq，并把req从fifo队列和红黑树队列剔除，将来磁盘驱动程序就是从queue_head链表取出req传输的
//这个合适的req，来源有:上次派发设置的next_rq;read req派发过多而选择的write req;fifo 队列上超时要传输的req，同手兼顾，有固定策略
static int deadline_dispatch_requests(struct request_queue *q, int force)
{
	struct deadline_data *dd = q->elevator->elevator_data;
    //如果fifo队列有read req,list_emptyf返回0，reads为1
	const int reads = !list_empty(&dd->fifo_list[READ]);
    //如果fifo队列有write req,list_emptyf返回0，writes为1
	const int writes = !list_empty(&dd->fifo_list[WRITE]);
	struct request *rq;
	int data_dir;

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
    //fifo队列有read req
	if (reads) {
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[READ]));
        //fifo队列有write req要传送给驱动，并且write req被饥饿次数达到上限，就强制选择跳转选择write req
        //防止一直选择read req给驱动传输，write req得不到选择而starve饥饿，每次write req得不到选择而饥饿
        //则starved++,writes_starved是饥饿的次数上限，starved大于writes_starved，就强制选择write req
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

		dd->starved = 0;
        //下面选择write req，就一个赋值操作
		data_dir = WRITE;

		goto dispatch_find_request;
	}

	return 0;

dispatch_find_request:
	/*
	 * we are not running a batch, find best request for selected data_dir
	 */
	//deadline_check_fifo如果deadline fifo队列有超时的req要传输返回1，next_rq没有暂存req，两个条件if都成立
	if (deadline_check_fifo(dd, data_dir) || !dd->next_rq[data_dir]) {
		/*
		 * A deadline has expired, the last request was in the other
		 * direction, or we have run out of higher-sectored requests.
		 * Start again from the request with the earliest expiry time.
		 */
		//取出fifo队列头的req，最早入fifo队列的req
		rq = rq_entry_fifo(dd->fifo_list[data_dir].next);
	} else {
		/*
		 * The last req was the same dir and we have a next request in
		 * sort order. No expired requests so continue on from here.
		 */
		//否则直接取出next_rq暂存的req
		rq = dd->next_rq[data_dir];
	}
    //batching清0
	dd->batching = 0;

dispatch_request://调到这里，req直接来自next_rq或者fifo队列，这个req就要被发给驱动传输了
	/*
	 * rq is the selected appropriate request.
	 */
	//batching加1
	dd->batching++;
    //把req添加到rq的queue_head队列，设置新的next_rq，并把req从fifo队列和红黑树队列剔除，将来磁盘驱动程序就是从queue_head链表取出req传输的
	deadline_move_request(dd, rq);

	return 1;
}

static void deadline_exit_queue(struct elevator_queue *e)
{
	struct deadline_data *dd = e->elevator_data;

	BUG_ON(!list_empty(&dd->fifo_list[READ]));
	BUG_ON(!list_empty(&dd->fifo_list[WRITE]));

	kfree(dd);
}

/*
 * initialize elevator private data (deadline_data).
 */
static int deadline_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct deadline_data *dd;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	dd = kmalloc_node(sizeof(*dd), GFP_KERNEL | __GFP_ZERO, q->node);
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

	spin_lock_irq(q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(q->queue_lock);
	return 0;
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

static struct elevator_type iosched_deadline = {
	.ops = {
		.elevator_merge_fn = 		deadline_merge,
		.elevator_merged_fn =		deadline_merged_request,
		.elevator_merge_req_fn =	deadline_merged_requests,
		.elevator_dispatch_fn =		deadline_dispatch_requests,
		.elevator_add_req_fn =		deadline_add_request,
		.elevator_former_req_fn =	elv_rb_former_request,
		.elevator_latter_req_fn =	elv_rb_latter_request,
		.elevator_init_fn =		deadline_init_queue,
		.elevator_exit_fn =		deadline_exit_queue,
	},

	.elevator_attrs = deadline_attrs,
	.elevator_name = "deadline",
	.elevator_owner = THIS_MODULE,
};

static int __init deadline_init(void)
{
	return elv_register(&iosched_deadline);
}

static void __exit deadline_exit(void)
{
	elv_unregister(&iosched_deadline);
}

module_init(deadline_init);
module_exit(deadline_exit);

MODULE_AUTHOR("Jens Axboe");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("deadline IO scheduler");
