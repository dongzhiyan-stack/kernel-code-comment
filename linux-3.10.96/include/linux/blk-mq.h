#ifndef BLK_MQ_H
#define BLK_MQ_H

#include <linux/blkdev.h>
#include <linux/rh_kabi.h>
#include <linux/sbitmap.h>

struct blk_mq_tags;
struct blk_flush_queue;

struct blk_mq_cpu_notifier {
	struct list_head list;
	void *data;
	RH_KABI_REPLACE(void (*notify)(void *data, unsigned long action, unsigned int cpu),
			int (*notify)(void *data, unsigned long action, unsigned int cpu))
};

struct blk_mq_ctxmap {
	unsigned int size;
	unsigned int bits_per_word;
	struct blk_align_bitmap *map;
};
//����Ӳ�����нṹ
struct blk_mq_hw_ctx {
	struct {
		spinlock_t		lock;
        //���ɷ���req�ŵ�������У���blk_mq_request_bypass_insert()
		struct list_head	dispatch;//Ӳ����������̴򽻵�����������ϵ�rq�������Ϸ������̵İ�????
	} ____cacheline_aligned_in_smp;

	unsigned long		state;		/* BLK_MQ_S_* flags */

	RH_KABI_REPLACE(struct delayed_work	delayed_work,
		        struct delayed_work	delay_work)//����rq��work�߳�

	unsigned long		flags;		/* BLK_MQ_F_* flags */

	struct request_queue	*queue;//���̶�Ӧ�Ķ���
	unsigned int		queue_num;//Ӳ�����б��

	void			*driver_data;
    //��������Ӳ�����й������������и���?????��blk_mq_map_swqueue()��nr_ctx����ctxs[]������±꣬��ctxs[nr_ctx++]=ctxs��
    //ÿһ��blk_mq_ctx�������нṹ����nr_ctxΪ�����±꣬���浽ctxs[]�����ԣ�Ӧ����Ӳ�����й������������б�ţ�Ӳ�����п��Թ������
    //�������У�������Ӳ�����нṹblk_mq_hw_ctx�ĳ�Աctxs[nr_ctx++]=ctxs��nr_ctx׼ȷ˵��Ӳ�����й����ĵڼ����������а�
	unsigned int		nr_ctx;
    //�����������нṹ��ָ�����飬����������������нṹָ�룬һ��Ӳ�����п��Թ�������������нṹ��
    //ÿһ��������Ȼ�������нṹ��������ctxs[]��blk_mq_map_swqueue�и�ֵ
	struct blk_mq_ctx	**ctxs;

	RH_KABI_REPLACE(unsigned int		nr_ctx_map,
			atomic_t		wait_index)

	//RH_KABI_REPLACE(unsigned long		*ctx_map,
	//		unsigned long		*padding1)
	//blk_mq_insert_requests->blk_mq_hctx_mark_pending�У��������в���req�ˣ�Ȼ����������ж�Ӧ��ctx_map��bit��1������
    unsigned long		*ctx_map;
    unsigned long		*padding1;
    
	RH_KABI_REPLACE(struct request		**rqs,
			struct request		**padding2)

	RH_KABI_REPLACE(struct list_head	page_list,
			struct list_head	padding3)
	//blk_mq_init_hctx()��blk_mq_map_swqueue()�и�ֵ������Ӳ������ר����tags���±ߵ�struct blk_mq_tags	*sched_tags�ǵ����㷨��tags
    //bio��Ҫת����rqʱ,�ʹ�blk_mq_tags��static_rqsȡ��rq
	struct blk_mq_tags	*tags;

	unsigned long		queued;
	unsigned long		run;
#define BLK_MQ_MAX_DISPATCH_ORDER	10
	unsigned long		dispatched[BLK_MQ_MAX_DISPATCH_ORDER];

	unsigned int		queue_depth;	/* DEPRECATED: RHEL kABI padding, repurpose? */
	unsigned int		numa_node;
	RH_KABI_DEPRECATE(unsigned int, cmd_size)

	struct blk_mq_cpu_notifier	cpu_notifier;
	struct kobject		kobj;

	RH_KABI_EXTEND(struct delayed_work	run_work)
	//RH_KABI_EXTEND(cpumask_var_t		cpumask)
	cpumask_var_t		cpumask;
	//RH_KABI_EXTEND(int			next_cpu)
	int			next_cpu;
	//RH_KABI_EXTEND(int			next_cpu_batch)
	int			next_cpu_batch;

	RH_KABI_EXTEND(struct sbitmap ctx_map)

	//RH_KABI_EXTEND(atomic_t		nr_active)
	atomic_t		nr_active;

	RH_KABI_EXTEND(struct blk_flush_queue	*fq)
	RH_KABI_EXTEND(struct srcu_struct	queue_rq_srcu)
	RH_KABI_EXTEND(wait_queue_t		dispatch_wait)
	RH_KABI_EXTEND(void			*sched_data)
	
	//RH_KABI_EXTEND(struct blk_mq_tags	*sched_tags)
	//blk_mq_sched_alloc_tags()�з��丳ֵ���������㷨�йص�blk_mq_tags
	struct blk_mq_tags	*sched_tags;
	RH_KABI_EXTEND(struct blk_mq_ctx	*dispatch_from)
#ifdef CONFIG_BLK_DEBUG_FS
	RH_KABI_EXTEND(struct dentry		*debugfs_dir)
	RH_KABI_EXTEND(struct dentry		*sched_debugfs_dir)
#endif
	//RH_KABI_EXTEND(int			dispatch_busy)
	//Ӧ���Ǳ�ʾӲ�����з�æ
	int			dispatch_busy;
};

#ifdef __GENKSYMS__
struct blk_mq_reg {
	struct blk_mq_ops	*ops;
	unsigned int		nr_hw_queues;
	unsigned int		queue_depth;	/* max hw supported */
	unsigned int		reserved_tags;
	unsigned int		cmd_size;	/* per-request extra data */
	int			numa_node;
	unsigned int		timeout;
	unsigned int		flags;		/* BLK_MQ_F_* */
};
#else
//nvme_dev_add->blk_mq_alloc_tag_set->blk_mq_alloc_rq_maps->__blk_mq_alloc_rq_maps->__blk_mq_alloc_rq_map ����blk_mq_tag_setȥ����rq���У�
//������nvme_dev_add����������nr_hw_queues��queue_depth��Ӳ�����и����������ȵ���ʲô��ϵ???????????
struct blk_mq_tag_set {
	//RH_KABI_CONST struct blk_mq_ops  *ops;
	struct blk_mq_ops  *ops;
	unsigned int		nr_hw_queues;//Ӳ��������,blk_mq_alloc_tag_set�б�����Ϊ1��˵����Ϊkdump������ԭ��
	
	//��ү�ģ������Ժ���Ϊqueue_depth��֧�ֵ����Ӳ��������?���ǵģ�ӦΪ��һ��Ӳ�����������֧�ֵ�req�����ɣ���ν������Ⱦ���
	//һ��������Զ����ɵĳ�Ա�����ɣ�����ĳ�ԱӦ�þ���req����__blk_mq_alloc_rq_maps->__blk_mq_alloc_rq_map ���ݶ����������
	//һ��Ӳ���������req
	unsigned int		queue_depth;	/* max hw supported ������� blk_mq_alloc_tag_set��������*/
	unsigned int		reserved_tags;
	unsigned int		cmd_size;	/* per-request extra data */
	int			numa_node;
	unsigned int		timeout;
	unsigned int		flags;		/* BLK_MQ_F_* */
	void			*driver_data;
    //��__blk_mq_alloc_rq_map()�����������blk_mq_tags�ṹ
	struct blk_mq_tags	**tags;//����ÿ��Ӳ�����ж�Ӧ��blk_mq_tags�ṹָ�룬һ��Ӳ�����ж�Ӧһ��������С����Ӳ�����б�ţ���0��ʼ
	struct mutex		tag_list_lock;
	struct list_head	tag_list;
    //���Ǹ��Իõ����飬��blk_mq_update_queue_map()�е�ע�ͣ��������±���CPU�ı�ţ������Ա��Ӳ�����еı��
    //�������Ա��blk_mq_alloc_tag_set()�з��䣬��CPU������ȡ������Ա��ֵȫ��0����0��Ӳ�����У����Ӳ������ֻ��һ���������ȫ��0��
    //���Ӳ��������3����mq_map[0]��mq_map[1]��mq_map[2]������0��1��2����������Ա����0������CPU��������Ӳ�����и��������
	unsigned int		*mq_map;
};
#endif

struct blk_mq_queue_data {
	struct request *rq;
	struct list_head *list;
	bool last;
};

/*
 * This structure is only for blk-mq and per request
 * for support some new blk-mq features, such as io
 * scheduler, blk-stat and so on.
 */
struct request_aux {
	int internal_tag;//__blk_mq_alloc_request�и�ֵ��tag���
	struct blk_issue_stat issue_stat;
}____cacheline_aligned_in_smp;

/* None of these function pointers are covered by RHEL kABI */
#ifdef __GENKSYMS__
typedef int (queue_rq_fn)(struct blk_mq_hw_ctx *, struct request *);
#else
typedef int (queue_rq_fn)(struct blk_mq_hw_ctx *, const struct blk_mq_queue_data *);
#endif

typedef bool (get_budget_fn)(struct blk_mq_hw_ctx *);
typedef void (put_budget_fn)(struct blk_mq_hw_ctx *);

typedef struct blk_mq_hw_ctx *(map_queue_fn)(struct request_queue *, const int);
#ifdef __GENKSYMS__
typedef struct blk_mq_hw_ctx *(alloc_hctx_fn)(struct blk_mq_reg *,unsigned int);
typedef void (free_hctx_fn)(struct blk_mq_hw_ctx *, unsigned int);
#endif
typedef enum blk_eh_timer_return (timeout_fn)(struct request *, bool);
typedef int (init_hctx_fn)(struct blk_mq_hw_ctx *, void *, unsigned int);
typedef void (exit_hctx_fn)(struct blk_mq_hw_ctx *, unsigned int);
typedef int (init_request_fn)(struct blk_mq_tag_set *set, struct request *,
		unsigned int, unsigned int);
typedef void (exit_request_fn)(struct blk_mq_tag_set *set, struct request *,
		unsigned int);
typedef int (reinit_request_fn)(void *, struct request *);

typedef void (busy_iter_fn)(struct blk_mq_hw_ctx *, struct request *, void *,
		bool);
typedef void (busy_tag_iter_fn)(struct request *, void *, bool);
typedef int (map_queues_fn)(struct blk_mq_tag_set *set);

struct blk_mq_aux_ops {
	reinit_request_fn	*reinit_request;
	map_queues_fn		*map_queues;

	/*
	 * Reserve budget before queue request, once .queue_rq is
	 * run, it is driver's responsibility to release the
	 * reserved budget. Also we have to handle failure case
	 * of .get_budget for avoiding I/O deadlock.
	 */
	get_budget_fn		*get_budget;
	put_budget_fn		*put_budget;
};
//nvme_dev_add()������Ϊnvme_mq_ops
struct blk_mq_ops {
	/*
	 * Queue request
	 */
	queue_rq_fn		*queue_rq;//nvme_queue_rq

	/*
	 * Map to specific hardware queue
	 *
	 * Reuse this pointer for aux ops.
	 */
	RH_KABI_REPLACE(map_queue_fn *map_queue, struct blk_mq_aux_ops *aux_ops)

	/*
	 * Called on request timeout
	 */
	RH_KABI_REPLACE(rq_timed_out_fn *timeout, timeout_fn *timeout)

	softirq_done_fn		*complete;//nvme_pci_complete_rq

#ifdef __GENKSYMS__
	/*
	 * Override for hctx allocations (should probably go)
	 * DEPRECATED: needed to preserve kABI.
	 */
	alloc_hctx_fn		*alloc_hctx;
	free_hctx_fn		*free_hctx;
#else
	/*
	 * Called for every command allocated by the block layer to allow
	 * the driver to set up driver specific data.
	 *
	 * Tag greater than or equal to queue_depth is for setting up
	 * flush request.
	 *
	 * Ditto for exit/teardown.
	 */
	init_request_fn		*init_request;
	exit_request_fn		*exit_request;
#endif

	/*
	 * Called when the block layer side of a hardware queue has been
	 * set up, allowing the driver to allocate/init matching structures.
	 * Ditto for exit/teardown.
	 */
	init_hctx_fn		*init_hctx;
	exit_hctx_fn		*exit_hctx;
};

enum {
	BLK_MQ_RQ_QUEUE_OK	= 0,	/* queued fine */
	BLK_MQ_RQ_QUEUE_BUSY	= 1,	/* requeue IO for later */
	BLK_MQ_RQ_QUEUE_ERROR	= 2,	/* end IO with error */

	/*
	 * BLK_MQ_RQ_QUEUE_DEV_BUSY is returned from the driver to the block layer if
	 * device related resources are unavailable, but the driver can guarantee
	 * that the queue will be rerun in the future once resources become
	 * available again. This is typically the case for device specific
	 * resources that are consumed for IO. If the driver fails allocating these
	 * resources, we know that inflight (or pending) IO will free these
	 * resource upon completion.
	 *
	 * This is different from BLK_MQ_RQ_QUEUE_BUSY in that it explicitly references
	 * a device specific resource. For resources of wider scope, allocation
	 * failure can happen without having pending IO. This means that we can't
	 * rely on request completions freeing these resources, as IO may not be in
	 * flight. Examples of that are kernel memory allocations, DMA mappings, or
	 * any other system wide resources.
	 */
	BLK_MQ_RQ_QUEUE_DEV_BUSY	= 3,

	BLK_MQ_F_SHOULD_MERGE	= 1 << 0,
	BLK_MQ_F_SHOULD_SORT	= 1 << 1,
	BLK_MQ_F_TAG_SHARED	= 1 << 2,
	BLK_MQ_F_SG_MERGE	= 1 << 3,
	BLK_MQ_F_BLOCKING	= 1 << 6,
	BLK_MQ_F_NO_SCHED	= 1 << 7,

	BLK_MQ_F_ALLOC_POLICY_START_BIT = 8,
	BLK_MQ_F_ALLOC_POLICY_BITS = 1,

	BLK_MQ_S_STOPPED	= 0,
	BLK_MQ_S_TAG_ACTIVE	= 1,
	BLK_MQ_S_SCHED_RESTART	= 2,

	BLK_MQ_MAX_DEPTH	= 10240,

	BLK_MQ_CPU_WORK_BATCH	= 8,
};
#define BLK_MQ_FLAG_TO_ALLOC_POLICY(flags) \
	((flags >> BLK_MQ_F_ALLOC_POLICY_START_BIT) & \
		((1 << BLK_MQ_F_ALLOC_POLICY_BITS) - 1))
#define BLK_ALLOC_POLICY_TO_MQ_FLAG(policy) \
	((policy & ((1 << BLK_MQ_F_ALLOC_POLICY_BITS) - 1)) \
		<< BLK_MQ_F_ALLOC_POLICY_START_BIT)

struct request_queue *blk_mq_init_queue(struct blk_mq_tag_set *);
struct request_queue *blk_mq_init_allocated_queue(struct blk_mq_tag_set *set,
						  struct request_queue *q);
int blk_mq_register_dev(struct device *, struct request_queue *);
void blk_mq_unregister_dev(struct device *, struct request_queue *);

int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set);
void blk_mq_free_tag_set(struct blk_mq_tag_set *set);

void blk_mq_flush_plug_list(struct blk_plug *plug, bool from_schedule);

void blk_mq_free_request(struct request *rq);
bool blk_mq_can_queue(struct blk_mq_hw_ctx *);

enum {
	BLK_MQ_REQ_NOWAIT	= (1 << 0), /* return when out of requests */
    //�ж�tag�Ƿ���Ԥ���ģ�blk_mq_get_driver_tag()������
	BLK_MQ_REQ_RESERVED	= (1 << 1), /* allocate from reserved pool */
	//blk_mq_sched_get_request()�е���������BLK_MQ_REQ_INTERNAL
	BLK_MQ_REQ_INTERNAL	= (1 << 2), /* allocate internal/sched tag */
	BLK_MQ_REQ_PREEMPT	= (1 << 3), /* set RQF_PREEMPT */
};

struct request *blk_mq_alloc_request(struct request_queue *q, int rw,
		unsigned int flags);
struct request *blk_mq_alloc_request_hctx(struct request_queue *q, int op,
		unsigned int flags, unsigned int hctx_idx);
struct request *blk_mq_tag_to_rq(struct blk_mq_tags *tags, unsigned int tag);

enum {
	BLK_MQ_UNIQUE_TAG_BITS = 16,
	BLK_MQ_UNIQUE_TAG_MASK = (1 << BLK_MQ_UNIQUE_TAG_BITS) - 1,
};

u32 blk_mq_unique_tag(struct request *rq);

static inline u16 blk_mq_unique_tag_to_hwq(u32 unique_tag)
{
	return unique_tag >> BLK_MQ_UNIQUE_TAG_BITS;
}

static inline u16 blk_mq_unique_tag_to_tag(u32 unique_tag)
{
	return unique_tag & BLK_MQ_UNIQUE_TAG_MASK;
}

struct blk_mq_hw_ctx *blk_mq_alloc_single_hw_queue(struct blk_mq_tag_set *, unsigned int, int);

int blk_mq_request_started(struct request *rq);
void blk_mq_start_request(struct request *rq);
void blk_mq_end_request(struct request *rq, int error);
void __blk_mq_end_request(struct request *rq, int error);

void blk_mq_requeue_request(struct request *rq, bool kick_requeue_list);
void blk_mq_add_to_requeue_list(struct request *rq, bool at_head,
				bool kick_requeue_list);
void blk_mq_kick_requeue_list(struct request_queue *q);
void blk_mq_delay_kick_requeue_list(struct request_queue *q, unsigned long msecs);
void blk_mq_complete_request(struct request *rq, int error);
void blk_mq_complete_request_sync(struct request *rq, int error);

bool blk_mq_queue_stopped(struct request_queue *q);
void blk_mq_stop_hw_queue(struct blk_mq_hw_ctx *hctx);
void blk_mq_start_hw_queue(struct blk_mq_hw_ctx *hctx);
void blk_mq_stop_hw_queues(struct request_queue *q);
void blk_mq_start_hw_queues(struct request_queue *q);
void blk_mq_start_stopped_hw_queues(struct request_queue *q, bool async);
void blk_mq_quiesce_queue(struct request_queue *q);
void blk_mq_unquiesce_queue(struct request_queue *q);
void blk_mq_delay_run_hw_queue(struct blk_mq_hw_ctx *hctx, unsigned long msecs);
bool blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx, bool async);
void blk_mq_run_hw_queues(struct request_queue *q, bool async);
void blk_mq_tagset_busy_iter(struct blk_mq_tag_set *tagset,
		busy_tag_iter_fn *fn, void *priv);
void blk_mq_freeze_queue(struct request_queue *q);
void blk_mq_unfreeze_queue(struct request_queue *q);
void blk_freeze_queue_start(struct request_queue *q);
void blk_mq_freeze_queue_wait(struct request_queue *q);
int blk_mq_freeze_queue_wait_timeout(struct request_queue *q,
				     unsigned long timeout);
int blk_mq_reinit_tagset(struct blk_mq_tag_set *set);

void blk_mq_update_nr_hw_queues(struct blk_mq_tag_set *set, int nr_hw_queues);

void blk_mq_quiesce_queue_nowait(struct request_queue *q);

/*
 * Driver command data is immediately after the request. So subtract request
 * size to get back to the original request.
 */
static inline struct request *blk_mq_rq_from_pdu(void *pdu)
{
	return pdu - sizeof(struct request);
}
static inline void *blk_mq_rq_to_pdu(struct request *rq)
{
	return (void *) rq + sizeof(*rq);
}

static inline struct request_aux *__rq_aux(struct request *rq,
					   struct request_queue *q)
{
	BUG_ON(!q->mq_ops);
	return (void *) rq + sizeof(*rq) + q->tag_set->cmd_size;
}

static inline struct request_aux *rq_aux(struct request *rq)
{
	return __rq_aux(rq, rq->q);
}
//���Ǹ���Ӳ�������������δ�q->queue_hw_ctx[i]����ȡ��Ӳ�����нṹ��
#define queue_for_each_hw_ctx(q, hctx, i)				\
	for ((i) = 0; (i) < (q)->nr_hw_queues &&			\
	     ({ hctx = (q)->queue_hw_ctx[i]; 1; }); (i)++)

#define hctx_for_each_ctx(hctx, ctx, i)					\
	for ((i) = 0; (i) < (hctx)->nr_ctx &&				\
	     ({ ctx = (hctx)->ctxs[(i)]; 1; }); (i)++)

#endif