#ifndef INT_BLK_MQ_TAG_H
#define INT_BLK_MQ_TAG_H

#include "blk-mq.h"

/*
 * Tag address space map.
 */
#ifdef __GENKSYMS__
struct blk_mq_tags;
#else

//nvme_dev_add->blk_mq_alloc_tag_set->blk_mq_alloc_rq_maps->__blk_mq_alloc_rq_maps->__blk_mq_alloc_rq_map->blk_mq_alloc_rq_map
//..->blk_mq_init_tags，中分配blk_mq_tags，设置其成员static_rqs、rqs、nr_tags、nr_reserved_tags

//每个硬件队列对应一个blk_mq_tags，硬件队列结构是blk_mq_hw_ctx，二者都代表硬件队列吧，但是意义不一样，blk_mq_hw_ctx从整理上描述
//硬件队列，blk_mq_tags主要用于从这里取出request吧,是的，bio转换成req时，就是从blk_mq_tags的static_rqs[]数组分配空闲的req吧
//blk_mq_hw_ctx结构的成员blk_mq_tag_set的tags[]指针数组保存每个硬件队列独有的blk_mq_tags
struct blk_mq_tags {
	unsigned int nr_tags;//来自set->queue_depth，一个硬件队列的队列深度，见blk_mq_init_tags()
	
	//static_rqs[]里空闲的request的数组下标的偏移，见blk_mq_get_tag()。再深入一步，blk_mq_get_driver_tag->blk_mq_tag_is_reserved，好像
	//nr_reserved_tags是预留的tag总数，比如，static_rqs[]数组共有100个成员，nr_reserved_tags是70，那就是预留70个，预留的分配完了，那就从
	//剩余的30个分配?????这些req的下标是70+0/1/2/3等。static_rqs[tag]数组下标用tag变量表示，一个tag一个req，很关键!!!!!
	unsigned int nr_reserved_tags;

	atomic_t active_queues;
    //这个bitmap_tags，应该用来标识static_rqs[]数组里哪个request被分配使用了，可以理解成一个bit位0/1标识该request是否被分配了
    //blk_mq_put_tag去除tag，blk_mq_get_tag()获取tag
	struct sbitmap_queue bitmap_tags;
	struct sbitmap_queue breserved_tags;

/*在分配req时，要从blk_mq_tags里分配一个tag，见blk_mq_alloc_rqs。启动req硬件传输前，也要从blk_mq_tags里分配一个空闲tag，见
blk_mq_get_driver_tag，看最后都调用blk_mq_get_tag从bitmap_tags得到一个空闲bit，代表的空闲的tag，有必要执行两次吗，啥意思
?????????????????????????????*/

    //在blk_mq_get_driver_tag()->blk_mq_get_tag，hctx->tags->rqs[req->tag]=req，req来自进程的plug->mq_list链表，赋值后就建立了req与硬件队列的关系
	struct request **rqs;//在__blk_mq_alloc_request()这里边保存的req是刚从static_rqs[]得到的空闲的req

    /*static_rqs[]里的req总数硬件队列同时最多支持的，bio转req时都要从static_rqs[]尝试得到一个空闲的，得不到就要休眠等待
     nvme硬件传输已有的req，传输完成后释放掉，static_rqs[]就有空闲的req可以分配了。见blk_mq_get_tag()
     */
	//static_rqs指针数组，该数组一个成员保存每一层队列深度对应的request结构首地址，硬件队列每一层深度，对应一个request结构
	//分配过程见__blk_mq_alloc_rq_map->blk_mq_alloc_rqs。使用过程见blk_mq_get_tag(),更详细见上边nr_reserved_tags变量的注释
	struct request **static_rqs;//bio需要转换成rq,从static_rqs取出rq

	//blk_mq_alloc_rqs()中分配page,然后添加到page_list，
	struct list_head page_list;
};
#endif


extern struct blk_mq_tags *blk_mq_init_tags(unsigned int nr_tags, unsigned int reserved_tags, int node, int alloc_policy);
extern void blk_mq_free_tags(struct blk_mq_tags *tags);

extern unsigned int blk_mq_get_tag(struct blk_mq_alloc_data *data);
extern void blk_mq_put_tag(struct blk_mq_hw_ctx *hctx, struct blk_mq_tags *tags,
			   struct blk_mq_ctx *ctx, unsigned int tag);
extern bool blk_mq_has_free_tags(struct blk_mq_tags *tags);
extern int blk_mq_tag_update_depth(struct blk_mq_hw_ctx *hctx,
					struct blk_mq_tags **tags,
					unsigned int depth, bool can_grow);
extern void blk_mq_tag_wakeup_all(struct blk_mq_tags *tags, bool);
void blk_mq_queue_tag_busy_iter(struct request_queue *q, busy_iter_fn *fn,
		void *priv);

static inline struct sbq_wait_state *bt_wait_ptr(struct sbitmap_queue *bt,
						 struct blk_mq_hw_ctx *hctx)
{
	if (!hctx)
		return &bt->ws[0];
	return sbq_wait_ptr(bt, &hctx->wait_index);
}

enum {
	BLK_MQ_TAG_CACHE_MIN	= 1,
	BLK_MQ_TAG_CACHE_MAX	= 64,
};

enum {
	BLK_MQ_TAG_FAIL		= -1U,
	BLK_MQ_TAG_MIN		= BLK_MQ_TAG_CACHE_MIN,
	BLK_MQ_TAG_MAX		= BLK_MQ_TAG_FAIL - 1,
};

extern bool __blk_mq_tag_busy(struct blk_mq_hw_ctx *);
extern void __blk_mq_tag_idle(struct blk_mq_hw_ctx *);

static inline bool blk_mq_tag_busy(struct blk_mq_hw_ctx *hctx)
{
	if (!(hctx->flags & BLK_MQ_F_TAG_SHARED))
		return false;

	return __blk_mq_tag_busy(hctx);
}

static inline void blk_mq_tag_idle(struct blk_mq_hw_ctx *hctx)
{
	if (!(hctx->flags & BLK_MQ_F_TAG_SHARED))
		return;

	__blk_mq_tag_idle(hctx);
}

/*
 * This helper should only be used for flush request to share tag
 * with the request cloned from, and both the two requests can't be
 * in flight at the same time. The caller has to make sure the tag
 * can't be freed.
 */
static inline void blk_mq_tag_set_rq(struct blk_mq_hw_ctx *hctx,
		unsigned int tag, struct request *rq)
{
	hctx->tags->rqs[tag] = rq;
}

static inline bool blk_mq_tag_is_reserved(struct blk_mq_tags *tags,
					  unsigned int tag)
{
	return tag < tags->nr_reserved_tags;
}

#endif
