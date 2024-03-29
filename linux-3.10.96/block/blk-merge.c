/*
 * Functions related to segment and merge handling
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>

#include "blk.h"

static unsigned int __blk_recalc_rq_segments(struct request_queue *q,
					     struct bio *bio)
{
	struct bio_vec *bv, *bvprv = NULL;
	int cluster, i, high, highprv = 1;
	unsigned int seg_size, nr_phys_segs;
	struct bio *fbio, *bbio;

	if (!bio)
		return 0;

	fbio = bio;
	cluster = blk_queue_cluster(q);
	seg_size = 0;
	nr_phys_segs = 0;
	for_each_bio(bio) {
		bio_for_each_segment(bv, bio, i) {
			/*
			 * the trick here is making sure that a high page is
			 * never considered part of another segment, since that
			 * might change with the bounce page.
			 */
			high = page_to_pfn(bv->bv_page) > queue_bounce_pfn(q);
			if (high || highprv)
				goto new_segment;
			if (cluster) {
				if (seg_size + bv->bv_len
				    > queue_max_segment_size(q))
					goto new_segment;
				if (!BIOVEC_PHYS_MERGEABLE(bvprv, bv))
					goto new_segment;
				if (!BIOVEC_SEG_BOUNDARY(q, bvprv, bv))
					goto new_segment;

				seg_size += bv->bv_len;
				bvprv = bv;
				continue;
			}
new_segment:
			if (nr_phys_segs == 1 && seg_size >
			    fbio->bi_seg_front_size)
				fbio->bi_seg_front_size = seg_size;

			nr_phys_segs++;
			bvprv = bv;
			seg_size = bv->bv_len;
			highprv = high;
		}
		bbio = bio;
	}

	if (nr_phys_segs == 1 && seg_size > fbio->bi_seg_front_size)
		fbio->bi_seg_front_size = seg_size;
	if (seg_size > bbio->bi_seg_back_size)
		bbio->bi_seg_back_size = seg_size;

	return nr_phys_segs;
}

void blk_recalc_rq_segments(struct request *rq)
{
	rq->nr_phys_segments = __blk_recalc_rq_segments(rq->q, rq->bio);
}

void blk_recount_segments(struct request_queue *q, struct bio *bio)
{
	struct bio *nxt = bio->bi_next;

	bio->bi_next = NULL;
	bio->bi_phys_segments = __blk_recalc_rq_segments(q, bio);
	bio->bi_next = nxt;
	bio->bi_flags |= (1 << BIO_SEG_VALID);
}
EXPORT_SYMBOL(blk_recount_segments);

static int blk_phys_contig_segment(struct request_queue *q, struct bio *bio,
				   struct bio *nxt)
{
	if (!blk_queue_cluster(q))
		return 0;

	if (bio->bi_seg_back_size + nxt->bi_seg_front_size >
	    queue_max_segment_size(q))
		return 0;

	if (!bio_has_data(bio))
		return 1;

	if (!BIOVEC_PHYS_MERGEABLE(__BVEC_END(bio), __BVEC_START(nxt)))
		return 0;

	/*
	 * bio and nxt are contiguous in memory; check if the queue allows
	 * these two to be merged into one
	 */
	if (BIO_SEG_BOUNDARY(q, bio, nxt))
		return 1;

	return 0;
}

//把bio的待传输的文件数据的内存地址bvec->bv_pag+bvec->bv_offset设置到sg
static void
__blk_segment_map_sg(struct request_queue *q, struct bio_vec *bvec,
		     struct scatterlist *sglist, struct bio_vec **bvprv,
		     struct scatterlist **sg, int *nsegs, int *cluster)
{

	int nbytes = bvec->bv_len;

	if (*bvprv && *cluster) {
		if ((*sg)->length + nbytes > queue_max_segment_size(q))
			goto new_segment;

		if (!BIOVEC_PHYS_MERGEABLE(*bvprv, bvec))
			goto new_segment;
		if (!BIOVEC_SEG_BOUNDARY(q, *bvprv, bvec))
			goto new_segment;

		(*sg)->length += nbytes;
	} else {
new_segment:
		if (!*sg)
			*sg = sglist;
		else {
			/*
			 * If the driver previously mapped a shorter
			 * list, we could see a termination bit
			 * prematurely unless it fully inits the sg
			 * table on each mapping. We KNOW that there
			 * must be more entries here or the driver
			 * would be buggy, so force clear the
			 * termination bit to avoid doing a full
			 * sg_init_table() in drivers for each command.
			 */
			sg_unmark_end(*sg);
			*sg = sg_next(*sg);
		}
        //把bio的待传输的文件数据的内存地址bvec->bv_pag+bvec->bv_offset设置到sg
		sg_set_page(*sg, bvec->bv_page, nbytes, bvec->bv_offset);
		(*nsegs)++;
	}
	*bvprv = bvec;
}

/*
 * map a request to scatterlist, return number of sg entries setup. Caller
 * must make sure sg can hold rq->nr_phys_segments entries
 */
//先遍历req上的每一个bio，再得到每个bio的bio_vec，把bio对应的文件数据在内存中的首地址bvec->bv_pag+bvec->bv_offset写入scatterlist
//scatterlist是磁盘数据DMA传输有关的数据结构
int blk_rq_map_sg(struct request_queue *q, struct request *rq,
		  struct scatterlist *sglist)
{
	struct bio_vec *bvec, *bvprv;
	struct req_iterator iter;
	struct scatterlist *sg;
	int nsegs, cluster;

	nsegs = 0;
	cluster = blk_queue_cluster(q);

	/*
	 * for each bio in rq
	 */
	bvprv = NULL;
	sg = NULL;
  //先遍历req上的每一个bio，再得到每个bio的bio_vec，bio_vec是bio对应的文件数据在内存中的地址，一个bio可能对应多个bio_vec
  //一个bio代表一片连续的磁盘空间，一个bio_vec代表一个page页内存，bvec->bv_pag+bvec->bv_offset 是内存中文件数据的首地址，实际IO数据传输时，
  //是使用DMA把内存中的文件数据自动传输到磁盘控制器。这个循环是把bio对应的文件数据在内存中的首地址依次写入sg。sg DMA数据传输时使用。
	rq_for_each_segment(bvec, rq, iter) {
        //把bio的待传输的文件数据的内存地址bvec->bv_pag+bvec->bv_offset设置到sg
		__blk_segment_map_sg(q, bvec, sglist, &bvprv, &sg,
				     &nsegs, &cluster);
	} /* segments in rq */


	if (unlikely(rq->cmd_flags & REQ_COPY_USER) &&
	    (blk_rq_bytes(rq) & q->dma_pad_mask)) {
		unsigned int pad_len =
			(q->dma_pad_mask & ~blk_rq_bytes(rq)) + 1;

		sg->length += pad_len;
		rq->extra_len += pad_len;
	}

	if (q->dma_drain_size && q->dma_drain_needed(rq)) {
		if (rq->cmd_flags & REQ_WRITE)
			memset(q->dma_drain_buffer, 0, q->dma_drain_size);

		sg->page_link &= ~0x02;
		sg = sg_next(sg);
		sg_set_page(sg, virt_to_page(q->dma_drain_buffer),
			    q->dma_drain_size,
			    ((unsigned long)q->dma_drain_buffer) &
			    (PAGE_SIZE - 1));
		nsegs++;
		rq->extra_len += q->dma_drain_size;
	}

	if (sg)
		sg_mark_end(sg);

	return nsegs;
}
EXPORT_SYMBOL(blk_rq_map_sg);

/**
 * blk_bio_map_sg - map a bio to a scatterlist
 * @q: request_queue in question
 * @bio: bio being mapped
 * @sglist: scatterlist being mapped
 *
 * Note:
 *    Caller must make sure sg can hold bio->bi_phys_segments entries
 *
 * Will return the number of sg entries setup
 */
int blk_bio_map_sg(struct request_queue *q, struct bio *bio,
		   struct scatterlist *sglist)
{
	struct bio_vec *bvec, *bvprv;
	struct scatterlist *sg;
	int nsegs, cluster;
	unsigned long i;

	nsegs = 0;
	cluster = blk_queue_cluster(q);

	bvprv = NULL;
	sg = NULL;
	bio_for_each_segment(bvec, bio, i) {
		__blk_segment_map_sg(q, bvec, sglist, &bvprv, &sg,
				     &nsegs, &cluster);
	} /* segments in bio */

	if (sg)
		sg_mark_end(sg);

	BUG_ON(bio->bi_phys_segments && nsegs > bio->bi_phys_segments);
	return nsegs;
}
EXPORT_SYMBOL(blk_bio_map_sg);

static inline int ll_new_hw_segment(struct request_queue *q,
				    struct request *req,
				    struct bio *bio)
{
	int nr_phys_segs = bio_phys_segments(q, bio);

   //应该req是合并bio的nr_phys_segs后的物理段数是否超过rq队列的阈值??????，应该就是对应的磁盘扇区个数吧，或者内存page个数
	if (req->nr_phys_segments + nr_phys_segs > queue_max_segments(q))
		goto no_merge;

	if (bio_integrity(bio) && blk_integrity_merge_bio(q, req, bio))
		goto no_merge;

	/*
	 * This will form the start of a new hw segment.  Bump both
	 * counters.
	 */
	//req->nr_phys_segments增加新的bio的物理段数
	req->nr_phys_segments += nr_phys_segs;
	return 1;

no_merge:
	req->cmd_flags |= REQ_NOMERGE;
	if (req == q->last_merge)
		q->last_merge = NULL;
	return 0;
}
//合并本次的bio到rq
int ll_back_merge_fn(struct request_queue *q, struct request *req,
		     struct bio *bio)
{
    //rq和bio操作的磁盘地址范围，合并后是否超出磁盘最大空间
	if (blk_rq_sectors(req) + bio_sectors(bio) >
	    blk_rq_get_max_sectors(req)) {
		req->cmd_flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}
    //对req->biotail的bi_phys_segments和bi_next设置新的值???????
	if (!bio_flagged(req->biotail, BIO_SEG_VALID))
		blk_recount_segments(q, req->biotail);
    //对bio的bi_phys_segments和bi_next设置新的值???????
	if (!bio_flagged(bio, BIO_SEG_VALID))
		blk_recount_segments(q, bio);

	return ll_new_hw_segment(q, req, bio);
}

int ll_front_merge_fn(struct request_queue *q, struct request *req,
		      struct bio *bio)
{
	if (blk_rq_sectors(req) + bio_sectors(bio) >
	    blk_rq_get_max_sectors(req)) {
		req->cmd_flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}
	if (!bio_flagged(bio, BIO_SEG_VALID))
		blk_recount_segments(q, bio);
	if (!bio_flagged(req->bio, BIO_SEG_VALID))
		blk_recount_segments(q, req->bio);

	return ll_new_hw_segment(q, req, bio);
}

static int ll_merge_requests_fn(struct request_queue *q, struct request *req,
				struct request *next)
{
	int total_phys_segments;
	unsigned int seg_size =
		req->biotail->bi_seg_back_size + next->bio->bi_seg_front_size;

	/*
	 * First check if the either of the requests are re-queued
	 * requests.  Can't merge them if they are.
	 */
	if (req->special || next->special)
		return 0;

	/*
	 * Will it become too large?
	 */
	if ((blk_rq_sectors(req) + blk_rq_sectors(next)) >
	    blk_rq_get_max_sectors(req))
		return 0;
    
    //req和next的nr_phys_segments累加
	total_phys_segments = req->nr_phys_segments + next->nr_phys_segments;
	if (blk_phys_contig_segment(q, req->biotail, next->bio)) {
		if (req->nr_phys_segments == 1)
			req->bio->bi_seg_front_size = seg_size;
		if (next->nr_phys_segments == 1)
			next->biotail->bi_seg_back_size = seg_size;
		total_phys_segments--;
	}

	if (total_phys_segments > queue_max_segments(q))
		return 0;

	if (blk_integrity_rq(req) && blk_integrity_merge_rq(q, req, next))
		return 0;

	/* Merge is OK... */
	req->nr_phys_segments = total_phys_segments;
	return 1;
}

/**
 * blk_rq_set_mixed_merge - mark a request as mixed merge
 * @rq: request to mark as mixed merge
 *
 * Description:
 *     @rq is about to be mixed merged.  Make sure the attributes
 *     which can be mixed are set in each bio and mark @rq as mixed
 *     merged.
 */
void blk_rq_set_mixed_merge(struct request *rq)
{
	unsigned int ff = rq->cmd_flags & REQ_FAILFAST_MASK;
	struct bio *bio;

	if (rq->cmd_flags & REQ_MIXED_MERGE)
		return;

	/*
	 * @rq will no longer represent mixable attributes for all the
	 * contained bios.  It will just track those of the first one.
	 * Distributes the attributs to each bio.
	 */
	for (bio = rq->bio; bio; bio = bio->bi_next) {
		WARN_ON_ONCE((bio->bi_rw & REQ_FAILFAST_MASK) &&
			     (bio->bi_rw & REQ_FAILFAST_MASK) != ff);
		bio->bi_rw |= ff;
	}
	rq->cmd_flags |= REQ_MIXED_MERGE;
}
//next合并打了req，没用了，这个next从in flight队列剔除掉，顺便执行part_round_stats更新io_ticks IO使用率计数
//???????????????为什么不增加IO统计数据的merge这个IO合并数呢?
static void blk_account_io_merge(struct request *req)
{
	if (blk_do_io_stat(req)) {
		struct hd_struct *part;
		int cpu;

		cpu = part_stat_lock();
		part = req->part;
        //更新主块设备和块设备分区的time_in_queue和io_ticks数据
		part_round_stats(cpu, part);
        //减少in flight队列的req计数
		part_dec_in_flight(part, rq_data_dir(req));

		hd_struct_put(part);
		part_stat_unlock();
	}
}

/*
 * Has to be called with the request spinlock acquired
 */
//尝试把next合并到req后边，并更新IO使用率数据。然后调用IO调度算法的elevator_merge_req_fn回调函数，当为deadline调度算法时，执行过程是:
//next已经合并到了req后,在fifo队列里，把req移动到next节点的位置，更新req的超时时间。从fifo队列和红黑树剔除next,还更新dd->next_rq[]
//赋值next的下一个req。因为rq合并了next，扇区结束地址变大了，则rq从hash队列中删除掉再重新按照扇区结束地址在hash队列中排序。
static int attempt_merge(struct request_queue *q, struct request *req,
			  struct request *next)//把next合并到req后边，req来自比如q->last_merge或hash队列的req
{
	if (!rq_mergeable(req) || !rq_mergeable(next))
		return 0;

	if (!blk_check_merge_flags(req->cmd_flags, next->cmd_flags))
		return 0;

	/*
	 * not contiguous
	 */
	//检查req扇区范围后边紧挨着next，没有紧挨着返回0
	if (blk_rq_pos(req) + blk_rq_sectors(req) != blk_rq_pos(next))
		return 0;

	if (rq_data_dir(req) != rq_data_dir(next)
	    || req->rq_disk != next->rq_disk
	    || next->special)
		return 0;

	if (req->cmd_flags & REQ_WRITE_SAME &&
	    !blk_write_same_mergeable(req->bio, next->bio))
		return 0;

	/*
	 * If we are allowed to merge, then append bio list
	 * from next to rq and release next. merge_requests_fn
	 * will have updated segment counts, update sector
	 * counts here.
	 */
	//在这里更新req->nr_phys_segments，扇区总数，因为要把next合并到req后边吧
	if (!ll_merge_requests_fn(q, req, next))
		return 0;

	/*
	 * If failfast settings disagree or any of the two is already
	 * a mixed merge, mark both as mixed before proceeding.  This
	 * makes sure that all involved bios have mixable attributes
	 * set properly.
	 */
	if ((req->cmd_flags | next->cmd_flags) & REQ_MIXED_MERGE ||
	    (req->cmd_flags & REQ_FAILFAST_MASK) !=
	    (next->cmd_flags & REQ_FAILFAST_MASK)) {
		blk_rq_set_mixed_merge(req);
		blk_rq_set_mixed_merge(next);
	}

	/*
	 * At this point we have either done a back merge
	 * or front merge. We need the smaller start_time of
	 * the merged requests to be the current request
	 * for accounting purposes.
	 */
	if (time_after(req->start_time, next->start_time))//如果next->start_time更小则赋值于req->start_time
		req->start_time = next->start_time;
    
    //一个req对应了多个bio，req->biotail应该是指向next上的第一个bio吧
	req->biotail->bi_next = next->bio;
    //biotail貌似指向了next的最后一个bio??????????
	req->biotail = next->biotail;
    //req吞并了next的磁盘空间范围
	req->__data_len += blk_rq_bytes(next);
    
    //调用IO调度算法的elevator_merge_req_fn回调函数,
    //在这里，next已经合并到了rq,在fifo队列里，把req移动到next节点的位置，更新req的超时时间。从fifo队列和红黑树剔除next,
    //还更新dd->next_rq[]赋值next的下一个req。因为rq合并了next，扇区结束地址变大了，则rq从hash队列中删除掉再重新再hash中排序
	elv_merge_requests(q, req, next);

	/*
	 * 'next' is going away, so update stats accordingly
	 */
	//next合并打了req，没用了，这个next从in flight队列剔除掉，顺便执行part_round_stats更新io_ticks IO使用率计数
	blk_account_io_merge(next);
    
    //req优先级，cfq调度算法的概念
	req->ioprio = ioprio_best(req->ioprio, next->ioprio);
	if (blk_rq_cpu_valid(next))
		req->cpu = next->cpu;

	/* owner-ship of bio passed from next to req */
	next->bio = NULL;
    //释放next这个req
	__blk_put_request(q, next);
	return 1;
}

//blk_queue_bio->attempt_back_merge 传说中的更高阶的合并吧，比如原IO调度算法队列挨着的req1和req2，代表的磁盘空间范围分别是req1:0~5，
//req2:11~16，新的待合并的bio的磁盘空间是6~10,则先执行bio_attempt_back_merge()把bio后项合并到req1,此时req1:0~10，显然此时req1和req2可以
//进行二次合并，attempt_back_merge()函数就是这个作用吧，该函数的struct request *next就像举例的req2。合并成功返回1，否则0

//之前req发生了后项合并,req的磁盘空间向后增大,从算法队列(deadline的红黑树队列)取出req的下一个req即next,再次尝试把next合并到req后边
int attempt_back_merge(struct request_queue *q, struct request *rq)
{
    //只是从IO调度算法队列里取出rq的下一个rq给next，调用的函数elv_rb_latter_request(deadline算法)或noop_latter_request(noop算法)
	struct request *next = elv_latter_request(q, rq);

    //这是尝试把next(举例中的req2)合并到rq(举例中的合并bio后的req1)，我有个疑问，既然会发生二次合并，那也可以发生三次合并呀，这里应该是
    //个循环处理，然后合并呀????????????
	if (next)
		return attempt_merge(q, rq, next);//把next合并到req，把next剔除掉，做一些剔除next的收尾处理,并更新IO使用率数据

    //如果req没有next req，只能返回0
	return 0;
}
//之前req发生了前项合并,req的磁盘空间向前增大,从算法队列(deadline的红黑树队列)取出req的上一个req即prev,再次尝试把req合并到prev后边
int attempt_front_merge(struct request_queue *q, struct request *rq)
{
    //红黑树中取出req原来的前一个req,即prev
	struct request *prev = elv_former_request(q, rq);

	if (prev)//把rq合并到prev
		return attempt_merge(q, prev, rq);

	return 0;
}
//尝试把next合并到req后边，并更新IO使用率数据。然后调用IO调度算法的elevator_merge_req_fn回调函数，当为deadline调度算法时，执行过程是:
//next已经合并到了req后,在fifo队列里，把req移动到next节点的位置，更新req的超时时间。从fifo队列和红黑树剔除next,还更新dd->next_rq[]
//赋值next的下一个req。因为rq合并了next，扇区结束地址变大了，则rq从hash队列中删除掉再重新按照扇区结束地址在hash队列中排序。
int blk_attempt_req_merge(struct request_queue *q, struct request *rq,//rq是合并母体，比如q->last_merge或hash队列的req
			  struct request *next)//next是本次新的req
{
	return attempt_merge(q, rq, next);//注意，这是把next后项合并到rq，只有后项合并!!!!!!为什么没有前项合并呢???????????????????
}
//对本次新的bio能否合并到rq做各个前期检查，检查通过返回true
bool blk_rq_merge_ok(struct request *rq, struct bio *bio)
{
    //rq和bio必须属于文件系统
	if (!rq_mergeable(rq) || !bio_mergeable(bio))
		return false;
    //还是检查二者属性吧
	if (!blk_check_merge_flags(rq->cmd_flags, bio->bi_rw))
		return false;

	/* different data direction or already started, don't merge */
    //是否都是读或者写
	if (bio_data_dir(bio) != rq_data_dir(rq))
		return false;

	/* must be same device and not a special request */
    //是否属于同一个disk磁盘
	if (rq->rq_disk != bio->bi_bdev->bd_disk || rq->special)
		return false;

	/* only merge integrity protected bio into ditto rq */
	if (bio_integrity(bio) != blk_integrity_rq(rq))
		return false;

	/* must be using the same buffer */
    //如果rq有REQ_WRITE_SAME属性，则貌似是比较两个bio对应的bh的实际内存page是否一样????????
	if (rq->cmd_flags & REQ_WRITE_SAME &&
	    !blk_write_same_mergeable(rq->bio, bio))
		return false;

	return true;
}
//检查bio和rq的磁盘范围是否挨着，挨着则可以合并，分为前项合并和后项合并
int blk_try_merge(struct request *rq, struct bio *bio)
{
    //rq的磁盘结束地址挨着bio的磁盘开始地址，rq向后合并本次的bio
	if (blk_rq_pos(rq) + blk_rq_sectors(rq) == bio->bi_sector)
		return ELEVATOR_BACK_MERGE;
    //bio的磁盘结束地址挨着rq的磁盘开始地址，rq向前合并本次的bio
	else if (blk_rq_pos(rq) - bio_sectors(bio) == bio->bi_sector)
		return ELEVATOR_FRONT_MERGE;
	return ELEVATOR_NO_MERGE;
}
