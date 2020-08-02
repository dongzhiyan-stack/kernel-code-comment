#ifndef BLK_MQ_SCHED_H
#define BLK_MQ_SCHED_H

void blk_mq_sched_free_hctx_data(struct request_queue *q,
				 void (*exit)(struct blk_mq_hw_ctx *));

struct request *blk_mq_sched_get_request(struct request_queue *q, struct bio *bio, unsigned int op, struct blk_mq_alloc_data *data);
void blk_mq_sched_put_request(struct request *rq);

void blk_mq_sched_request_inserted(struct request *rq);
bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
				struct request **merged_request);
bool __blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio);
bool blk_mq_sched_try_insert_merge(struct request_queue *q, struct request *rq);
void blk_mq_sched_restart(struct blk_mq_hw_ctx *hctx);

void blk_mq_sched_insert_request(struct request *rq, bool at_head,
				 bool run_queue, bool async);
void blk_mq_sched_insert_requests(struct request_queue *q,
				  struct blk_mq_ctx *ctx,
				  struct list_head *list, bool run_queue_async);

void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx);
void blk_mq_sched_move_to_dispatch(struct blk_mq_hw_ctx *hctx,
			struct list_head *rq_list,
			struct request *(*get_rq)(struct blk_mq_hw_ctx *));

int blk_mq_init_sched(struct request_queue *q, struct elevator_type *e);
void blk_mq_exit_sched(struct request_queue *q, struct elevator_queue *e);

int blk_mq_sched_init_hctx(struct request_queue *q, struct blk_mq_hw_ctx *hctx,
			   unsigned int hctx_idx);
void blk_mq_sched_exit_hctx(struct request_queue *q, struct blk_mq_hw_ctx *hctx,
			    unsigned int hctx_idx);

int blk_mq_sched_init(struct request_queue *q);

//在IO调度器队列里查找是否有可以合并的req，找到则可以bio后项或前项合并到req，还会触发二次合并，还会对合并后的req在IO调度算法队列里重新排序
//这个合并跟软件队列和硬件队列没有半毛钱的关系吧
static inline bool
blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (!e || blk_queue_nomerges(q) || !bio_mergeable(bio))
		return false;

	return __blk_mq_sched_bio_merge(q, bio);
}

static inline int blk_mq_sched_get_rq_priv(struct request_queue *q,
					   struct request *rq,
					   struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (e && e->aux->ops.mq.get_rq_priv)
		return e->aux->ops.mq.get_rq_priv(q, rq, bio);

	return 0;
}

static inline void blk_mq_sched_put_rq_priv(struct request_queue *q,
					    struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (e && e->aux->ops.mq.put_rq_priv)
		e->aux->ops.mq.put_rq_priv(q, rq);
}

static inline bool
blk_mq_sched_allow_merge(struct request_queue *q, struct request *rq,
			 struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (e && e->aux->ops.mq.allow_merge)
		return e->aux->ops.mq.allow_merge(q, rq, bio);

	return true;
}

static inline void blk_mq_sched_started_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (e && e->aux->ops.mq.started_request)//no
		e->aux->ops.mq.started_request(rq);
}

static inline void blk_mq_sched_requeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (e && e->aux->ops.mq.requeue_request)
		e->aux->ops.mq.requeue_request(rq);
}

static inline bool blk_mq_sched_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct elevator_queue *e = hctx->queue->elevator;

	if (e && e->aux->ops.mq.has_work)
		return e->aux->ops.mq.has_work(hctx);

	return false;
}
//测试hctx->state是否设置了BLK_MQ_S_SCHED_RESTART位
static inline bool blk_mq_sched_needs_restart(struct blk_mq_hw_ctx *hctx)
{
	return test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);
}

#endif
