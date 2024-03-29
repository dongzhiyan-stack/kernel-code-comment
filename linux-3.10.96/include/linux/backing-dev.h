/*
 * include/linux/backing-dev.h
 *
 * low-level device information and state which is propagated up through
 * to high-level code.
 */

#ifndef _LINUX_BACKING_DEV_H
#define _LINUX_BACKING_DEV_H

#include <linux/percpu_counter.h>
#include <linux/log2.h>
#include <linux/flex_proportions.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/writeback.h>
#include <linux/atomic.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>

struct page;
struct device;
struct dentry;

/*
 * Bits in backing_dev_info.state
 */
enum bdi_state {
	BDI_wb_alloc,		/* Default embedded wb allocated */
	BDI_async_congested,	/* The async (write) queue is getting full */
	BDI_sync_congested,	/* The sync queue is getting full */
	BDI_registered,		/* bdi_register() was done */
	BDI_writeback_running,	/* Writeback is in progress */
	BDI_unused,		/* Available bits start here */
};

typedef int (congested_fn)(void *, int);

enum bdi_stat_item {
    //__set_page_dirty->account_page_dirtied标记脏页时，BDI_RECLAIMABLE的page加1，__delete_from_page_cache从pagecache中剔除page减1
	BDI_RECLAIMABLE,
  /*test_set_page_writeback判断page在回写则加1，这是在对page执行submit_bio把脏页刷回磁盘前前设置page的BDI_WRITEBACK标记.比如
    ext4_writepage->ext4_bio_write_page->set_page_writeback->test_set_page_writeback()。 在脏页回写完成执行
    end_page_writeback->test_clear_page_writeback减1*/
	BDI_WRITEBACK,
	/*__set_page_dirty->account_page_dirtied标记脏页时，BDI_DIRTIED的page加1，
	ext4_writepage->redirty_page_for_writepage->account_page_redirty在submit_bio前减1*/
	BDI_DIRTIED,//当前bdi块设备的脏页数
	BDI_WRITTEN, //当前bdi块设备已经回写的脏页数
	NR_BDI_STAT_ITEMS
};

#define BDI_STAT_BATCH (8*(1+ilog2(nr_cpu_ids)))

//简称wb，bdi_writeback来自bdi结构,一个块设备一个，即便是像dm这种虚拟的块设备，也是一个dm一个wb
struct bdi_writeback {
    //指向块设备的bdi
	struct backing_dev_info *bdi;	/* our parent bdi */
	unsigned int nr;
    //wb_check_old_data_flush()更新为当前系统时间
	unsigned long last_old_flush;	/* last old data flush */
    //脏数据回写dwork。work对应函数是bdi_writeback_workfn()。bdi_queue_work()中第一次启动。
	struct delayed_work dwork;	/* work item used for writeback */
    //__mark_inode_dirty()中把list_move(&inode->i_wb_list, &bdi->wb.b_dirty)把inode移动到bdi->wb.b_dirty
	struct list_head b_dirty;	/* dirty inodes */
    //queue_io()把wb->b_more_io成员移动到wb->b_io
	struct list_head b_io;		/* parked for writeback */
    //保存临时没来得及传输的inode，下次传输。requeue_io()把inode->i_wb_list移动到到wb->b_more_io, queue_io()把wb->b_more_io成员移动到wb->b_io
	struct list_head b_more_io;	/* parked for more writeback */
	spinlock_t list_lock;		/* protects the b_* lists */
};
//struct backing_dev_info ，简称bdi，在块设备初始化时来自运行队列struct request_queue 的q->backing_dev_info，一个块设备一个，
//即便是像dm这种虚拟的块设备，也是一个dm一个bdi
struct backing_dev_info {
	struct list_head bdi_list;
	unsigned long ra_pages;	/* max readahead in PAGE_CACHE_SIZE units */
    //脏页回写进程运行，wb_do_writeback()中设置BDI_writeback_running，该函数退出后清空BDI_writeback_running
	unsigned long state;	/* Always use atomic bitops on this */
	unsigned int capabilities; /* Device capabilities */
	congested_fn *congested_fn; /* Function pointer if device is md/dm */
	void *congested_data;	/* Pointer to aux data for congested func */

	char *name;//打印结果是"device"

	struct percpu_counter bdi_stat[NR_BDI_STAT_ITEMS];
    //bdi->bw_time_stamp是上次执行__bdi_update_bandwidth()计算bdi->dirty_ratelimit的系统时间
	unsigned long bw_time_stamp;	/* last time write bw is updated */
	unsigned long dirtied_stamp;//当前bdi块设备的脏页数
	//当前bdi块设备已经回写的脏页数
	unsigned long written_stamp;	/* pages written at bw_time_stamp */

    /*write_bandwidth、avg_write_bandwidth、dirty_ratelimit、balanced_dirty_ratelimit 的单位都是文件页page数，初值bdi_init()都是
     100MB字节对应的page数*/
    //bdi->write_bandwidth表示最近一段时间单位时间内bdi块设备回写磁盘的脏页数，见bdi_update_write_bandwidth()
	unsigned long write_bandwidth;	/* the estimated write bandwidth */
    //单位时间内bdi块设备回写磁盘的脏页数，缓慢接近bdi->write_bandwidth，见bdi_update_write_bandwidth()
	unsigned long avg_write_bandwidth; /* further smoothed write bw */

	/*
	 * The base dirty throttle rate, re-calculated on every 200ms.
	 * All the bdi tasks' dirty rate will be curbed under it.
	 * @dirty_ratelimit tracks the estimated @balanced_dirty_ratelimit
	 * in small steps and is much more smooth/stable than the latter.
	 */
	//dirty_ratelimit表示bdi块设备脏页速率限制page数，与balanced_dirty_ratelimit无限接近。见bdi_update_dirty_ratelimit()
	unsigned long dirty_ratelimit;
    //balanced_dirty_ratelimit表示因脏页平衡而脏页速率限制的page数，与bdi脏页产生速率和脏页回写磁盘速率有关，见bdi_update_dirty_ratelimit()
    //最大值是前一次单位时间内bdi块设备回写磁盘的脏页数avg_write_bandwidth。
	unsigned long balanced_dirty_ratelimit;

	struct fprop_local_percpu completions;
    //balance_dirty_pages()中进程脏页太多，并且bdi脏页太多，则bdi->dirty_exceeded=1表示脏页太多。然后进程可能休眠，
    //退出balance_dirty_pages()时再清0
	int dirty_exceeded;

	unsigned int min_ratio;
	unsigned int max_ratio, max_prop_frac;
    //wb在这里
	struct bdi_writeback wb;  /* default writeback info for this bdi */
	spinlock_t wb_lock;	  /* protects work_list & wb.dwork scheduling */

	struct list_head work_list;//bdi_queue_work()中把wb_writeback_work加入该链表

	struct device *dev;

	struct timer_list laptop_mode_wb_timer;//bdi定时器，blk_alloc_queue_node中初始化,定时器函数是laptop_mode_timer_fn

#ifdef CONFIG_DEBUG_FS
	struct dentry *debug_dir;
	struct dentry *debug_stats;
#endif
};

int bdi_init(struct backing_dev_info *bdi);
void bdi_destroy(struct backing_dev_info *bdi);

__printf(3, 4)
int bdi_register(struct backing_dev_info *bdi, struct device *parent,
		const char *fmt, ...);
int bdi_register_dev(struct backing_dev_info *bdi, dev_t dev);
void bdi_unregister(struct backing_dev_info *bdi);
int bdi_setup_and_register(struct backing_dev_info *, char *, unsigned int);
void bdi_start_writeback(struct backing_dev_info *bdi, long nr_pages,
			enum wb_reason reason);
void bdi_start_background_writeback(struct backing_dev_info *bdi);
void bdi_writeback_workfn(struct work_struct *work);
int bdi_has_dirty_io(struct backing_dev_info *bdi);
void bdi_wakeup_thread_delayed(struct backing_dev_info *bdi);
void bdi_lock_two(struct bdi_writeback *wb1, struct bdi_writeback *wb2);

extern spinlock_t bdi_lock;
extern struct list_head bdi_list;

extern struct workqueue_struct *bdi_wq;

static inline int wb_has_dirty_io(struct bdi_writeback *wb)
{
	return !list_empty(&wb->b_dirty) ||
	       !list_empty(&wb->b_io) ||
	       !list_empty(&wb->b_more_io);
}

static inline void __add_bdi_stat(struct backing_dev_info *bdi,
		enum bdi_stat_item item, s64 amount)
{
	__percpu_counter_add(&bdi->bdi_stat[item], amount, BDI_STAT_BATCH);
}

static inline void __inc_bdi_stat(struct backing_dev_info *bdi,
		enum bdi_stat_item item)
{
	__add_bdi_stat(bdi, item, 1);
}

static inline void inc_bdi_stat(struct backing_dev_info *bdi,
		enum bdi_stat_item item)
{
	unsigned long flags;

	local_irq_save(flags);
	__inc_bdi_stat(bdi, item);
	local_irq_restore(flags);
}

static inline void __dec_bdi_stat(struct backing_dev_info *bdi,
		enum bdi_stat_item item)
{
	__add_bdi_stat(bdi, item, -1);
}

static inline void dec_bdi_stat(struct backing_dev_info *bdi,
		enum bdi_stat_item item)
{
	unsigned long flags;

	local_irq_save(flags);
	__dec_bdi_stat(bdi, item);
	local_irq_restore(flags);
}

static inline s64 bdi_stat(struct backing_dev_info *bdi,
		enum bdi_stat_item item)
{
	return percpu_counter_read_positive(&bdi->bdi_stat[item]);
}

static inline s64 __bdi_stat_sum(struct backing_dev_info *bdi,
		enum bdi_stat_item item)
{
	return percpu_counter_sum_positive(&bdi->bdi_stat[item]);
}

static inline s64 bdi_stat_sum(struct backing_dev_info *bdi,
		enum bdi_stat_item item)
{
	s64 sum;
	unsigned long flags;

	local_irq_save(flags);
	sum = __bdi_stat_sum(bdi, item);
	local_irq_restore(flags);

	return sum;
}

extern void bdi_writeout_inc(struct backing_dev_info *bdi);

/*
 * maximal error of a stat counter.
 */
static inline unsigned long bdi_stat_error(struct backing_dev_info *bdi)
{
#ifdef CONFIG_SMP
	return nr_cpu_ids * BDI_STAT_BATCH;
#else
	return 1;
#endif
}

int bdi_set_min_ratio(struct backing_dev_info *bdi, unsigned int min_ratio);
int bdi_set_max_ratio(struct backing_dev_info *bdi, unsigned int max_ratio);

/*
 * Flags in backing_dev_info::capability
 *
 * The first three flags control whether dirty pages will contribute to the
 * VM's accounting and whether writepages() should be called for dirty pages
 * (something that would not, for example, be appropriate for ramfs)
 *
 * WARNING: these flags are closely related and should not normally be
 * used separately.  The BDI_CAP_NO_ACCT_AND_WRITEBACK combines these
 * three flags into a single convenience macro.
 *
 * BDI_CAP_NO_ACCT_DIRTY:  Dirty pages shouldn't contribute to accounting
 * BDI_CAP_NO_WRITEBACK:   Don't write pages back
 * BDI_CAP_NO_ACCT_WB:     Don't automatically account writeback pages
 *
 * These flags let !MMU mmap() govern direct device mapping vs immediate
 * copying more easily for MAP_PRIVATE, especially for ROM filesystems.
 *
 * BDI_CAP_MAP_COPY:       Copy can be mapped (MAP_PRIVATE)
 * BDI_CAP_MAP_DIRECT:     Can be mapped directly (MAP_SHARED)
 * BDI_CAP_READ_MAP:       Can be mapped for reading
 * BDI_CAP_WRITE_MAP:      Can be mapped for writing
 * BDI_CAP_EXEC_MAP:       Can be mapped for execution
 *
 * BDI_CAP_SWAP_BACKED:    Count shmem/tmpfs objects as swap-backed.
 */
#define BDI_CAP_NO_ACCT_DIRTY	0x00000001
#define BDI_CAP_NO_WRITEBACK	0x00000002
#define BDI_CAP_MAP_COPY	0x00000004
#define BDI_CAP_MAP_DIRECT	0x00000008
#define BDI_CAP_READ_MAP	0x00000010
#define BDI_CAP_WRITE_MAP	0x00000020
#define BDI_CAP_EXEC_MAP	0x00000040
#define BDI_CAP_NO_ACCT_WB	0x00000080
#define BDI_CAP_SWAP_BACKED	0x00000100
#define BDI_CAP_STABLE_WRITES	0x00000200

#define BDI_CAP_VMFLAGS \
	(BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP)

#define BDI_CAP_NO_ACCT_AND_WRITEBACK \
	(BDI_CAP_NO_WRITEBACK | BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_ACCT_WB)

#if defined(VM_MAYREAD) && \
	(BDI_CAP_READ_MAP != VM_MAYREAD || \
	 BDI_CAP_WRITE_MAP != VM_MAYWRITE || \
	 BDI_CAP_EXEC_MAP != VM_MAYEXEC)
#error please change backing_dev_info::capabilities flags
#endif

extern struct backing_dev_info default_backing_dev_info;
extern struct backing_dev_info noop_backing_dev_info;

int writeback_in_progress(struct backing_dev_info *bdi);

static inline int bdi_congested(struct backing_dev_info *bdi, int bdi_bits)
{
	if (bdi->congested_fn)
		return bdi->congested_fn(bdi->congested_data, bdi_bits);
	return (bdi->state & bdi_bits);
}

static inline int bdi_read_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, 1 << BDI_sync_congested);
}

static inline int bdi_write_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, 1 << BDI_async_congested);
}

static inline int bdi_rw_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, (1 << BDI_sync_congested) |
				  (1 << BDI_async_congested));
}

enum {
	BLK_RW_ASYNC	= 0,
	BLK_RW_SYNC	= 1,
};

void clear_bdi_congested(struct backing_dev_info *bdi, int sync);
void set_bdi_congested(struct backing_dev_info *bdi, int sync);
long congestion_wait(int sync, long timeout);
long wait_iff_congested(struct zone *zone, int sync, long timeout);
int pdflush_proc_obsolete(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);

static inline bool bdi_cap_stable_pages_required(struct backing_dev_info *bdi)
{
	return bdi->capabilities & BDI_CAP_STABLE_WRITES;
}

static inline bool bdi_cap_writeback_dirty(struct backing_dev_info *bdi)
{
	return !(bdi->capabilities & BDI_CAP_NO_WRITEBACK);
}

static inline bool bdi_cap_account_dirty(struct backing_dev_info *bdi)
{
	return !(bdi->capabilities & BDI_CAP_NO_ACCT_DIRTY);
}

static inline bool bdi_cap_account_writeback(struct backing_dev_info *bdi)
{
	/* Paranoia: BDI_CAP_NO_WRITEBACK implies BDI_CAP_NO_ACCT_WB */
	return !(bdi->capabilities & (BDI_CAP_NO_ACCT_WB |
				      BDI_CAP_NO_WRITEBACK));
}

static inline bool bdi_cap_swap_backed(struct backing_dev_info *bdi)
{
	return bdi->capabilities & BDI_CAP_SWAP_BACKED;
}

static inline bool mapping_cap_writeback_dirty(struct address_space *mapping)
{
	return bdi_cap_writeback_dirty(mapping->backing_dev_info);
}

static inline bool mapping_cap_account_dirty(struct address_space *mapping)
{
	return bdi_cap_account_dirty(mapping->backing_dev_info);
}

static inline bool mapping_cap_swap_backed(struct address_space *mapping)
{
	return bdi_cap_swap_backed(mapping->backing_dev_info);
}

static inline int bdi_sched_wait(void *word)
{
	schedule();
	return 0;
}

#endif		/* _LINUX_BACKING_DEV_H */
