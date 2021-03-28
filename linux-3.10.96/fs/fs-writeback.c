/*
 * fs/fs-writeback.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * Contains all the functions related to writing back and waiting
 * upon dirty inodes against superblocks, and writing back dirty
 * pages against inodes.  ie: data writeback.  Writeout of the
 * inode itself is not handled here.
 *
 * 10Apr2002	Andrew Morton
 *		Split out of fs/inode.c
 *		Additions for address_space-based writeback
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/kthread.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/tracepoint.h>
#include "internal.h"

/*
 * 4MB minimal write chunk size
 */
#define MIN_WRITEBACK_PAGES	(4096UL >> (PAGE_CACHE_SHIFT - 10))

/*
 * Passed into wb_writeback(), essentially a subset of writeback_control
 */
//初始化是:laptop_mode_timer_fn->bdi_start_writeback->__bdi_start_writeback()中分配wb_writeback_work并添加到bdi->work_list链表

//该结构临时分配，wb_check_old_data_flush()回刷历史脏数据、wb_check_background_flush()回刷超过阀值脏数据，都会临时分配一个
//wb_writeback_work并初始化
struct wb_writeback_work {
	long nr_pages;//wb_check_old_data_flush和wb_check_background_flush设置为LONG_MAX
	struct super_block *sb;//正常的脏页回写很少见设置这个sb
	unsigned long *older_than_this;
	enum writeback_sync_modes sync_mode;//wb_check_old_data_flush和wb_check_background_flush设置WB_SYNC_NONE，
	unsigned int tagged_writepages:1;
	unsigned int for_kupdate:1;//wb_check_old_data_flush()中置1
	unsigned int range_cyclic:1;
	unsigned int for_background:1;//wb_check_background_flush()中置1
	//old_data_flush模式设置WB_REASON_PERIODIC，background_flush模式设置为WB_REASON_BACKGROUND
	enum wb_reason reason;		/* why was writeback initiated? */

	struct list_head list;		/* pending work list */
	struct completion *done;	/* set if the caller waits */
};

/**
 * writeback_in_progress - determine whether there is writeback in progress
 * @bdi: the device's backing_dev_info structure.
 *
 * Determine whether there is writeback waiting to be handled against a
 * backing device.
 */
int writeback_in_progress(struct backing_dev_info *bdi)
{
	return test_bit(BDI_writeback_running, &bdi->state);
}
EXPORT_SYMBOL(writeback_in_progress);
//返回inode对应文件所在块设备的backing_dev_info结构
static inline struct backing_dev_info *inode_to_bdi(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	if (strcmp(sb->s_type->name, "bdev") == 0)
		return inode->i_mapping->backing_dev_info;

	return sb->s_bdi;
}

static inline struct inode *wb_inode(struct list_head *head)
{
	return list_entry(head, struct inode, i_wb_list);
}

/*
 * Include the creation of the trace points after defining the
 * wb_writeback_work structure and inline functions so that the definition
 * remains local to this file.
 */
#define CREATE_TRACE_POINTS
#include <trace/events/writeback.h>

static void bdi_wakeup_thread(struct backing_dev_info *bdi)
{
	spin_lock_bh(&bdi->wb_lock);
	if (test_bit(BDI_registered, &bdi->state))
		mod_delayed_work(bdi_wq, &bdi->wb.dwork, 0);
	spin_unlock_bh(&bdi->wb_lock);
}
//把struct wb_writeback_work *work加入到bdi->work_list链表，把bdi->wb.dwork 加入bdi_wq工作队列，并立即启动该work
static void bdi_queue_work(struct backing_dev_info *bdi,
			   struct wb_writeback_work *work)
{
	trace_writeback_queue(bdi, work);

	spin_lock_bh(&bdi->wb_lock);
	if (!test_bit(BDI_registered, &bdi->state)) {
		if (work->done)
			complete(work->done);
		goto out_unlock;
	}
    //把struct wb_writeback_work *work加入到bdi->work_list链表
	list_add_tail(&work->list, &bdi->work_list);
    //把bdi->wb.dwork 加入bdi_wq工作队列，并启动该work
	mod_delayed_work(bdi_wq, &bdi->wb.dwork, 0);
out_unlock:
	spin_unlock_bh(&bdi->wb_lock);
}
//这个函数应该初始化时执行一次
static void
__bdi_start_writeback(struct backing_dev_info *bdi, long nr_pages,
		      bool range_cyclic, enum wb_reason reason)
{
	struct wb_writeback_work *work;

	/*
	 * This is WB_SYNC_NONE writeback, so if allocation fails just
	 * wakeup the thread for old dirty data writeback
	 */
	work = kzalloc(sizeof(*work), GFP_ATOMIC);//分配wb_writeback_work
	if (!work) {
		trace_writeback_nowork(bdi);
		bdi_wakeup_thread(bdi);
		return;
	}

	work->sync_mode	= WB_SYNC_NONE;
	work->nr_pages	= nr_pages;
	work->range_cyclic = range_cyclic;
	work->reason	= reason;

	bdi_queue_work(bdi, work);//把work加入到bdi->work_list链表
}

/**
 * bdi_start_writeback - start writeback
 * @bdi: the backing device to write from
 * @nr_pages: the number of pages to write
 * @reason: reason why some writeback work was initiated
 *
 * Description:
 *   This does WB_SYNC_NONE opportunistic writeback. The IO is only
 *   started when this function returns, we make no guarantees on
 *   completion. Caller need not hold sb s_umount semaphore.
 *
 */
void bdi_start_writeback(struct backing_dev_info *bdi, long nr_pages,
			enum wb_reason reason)
{
	__bdi_start_writeback(bdi, nr_pages, true, reason);
}

/**
 * bdi_start_background_writeback - start background writeback
 * @bdi: the backing device to write from
 *
 * Description:
 *   This makes sure WB_SYNC_NONE background writeback happens. When
 *   this function returns, it is only guaranteed that for given BDI
 *   some IO is happening if we are over background dirty threshold.
 *   Caller need not hold sb s_umount semaphore.
 */
void bdi_start_background_writeback(struct backing_dev_info *bdi)
{
	/*
	 * We just wake up the flusher thread. It will perform background
	 * writeback as soon as there is no other work to do.
	 */
	trace_writeback_wake_background(bdi);
	bdi_wakeup_thread(bdi);
}

/*
 * Remove the inode from the writeback list it is on.
 */
void inode_wb_list_del(struct inode *inode)
{
	struct backing_dev_info *bdi = inode_to_bdi(inode);

	spin_lock(&bdi->wb.list_lock);
	list_del_init(&inode->i_wb_list);
	spin_unlock(&bdi->wb.list_lock);
}

/*
 * Redirty an inode: set its when-it-was dirtied timestamp and move it to the
 * furthest end of its superblock's dirty-inode list.
 *
 * Before stamping the inode's ->dirtied_when, we check to see whether it is
 * already the most-recently-dirtied inode on the b_dirty list.  If that is
 * the case then the inode must have been redirtied while it was being written
 * out and we don't reset its dirtied_when.
 */
//重新把inode移动到wb->b_dirty链表，并可能会再次更新inode的脏时间inode->dirtied_when
static void redirty_tail(struct inode *inode, struct bdi_writeback *wb)
{
	assert_spin_locked(&wb->list_lock);
    
	if (!list_empty(&wb->b_dirty)) {
		struct inode *tail;
        //取出wb->b_dirty链表上的第一个脏inode
		tail = wb_inode(wb->b_dirty.next);
        //如果inode的脏时间比wb->b_dirty链表上的第一个脏inode的脏时间还小还老，则把inode的脏时间更新为当前时间
		if (time_before(inode->dirtied_when, tail->dirtied_when))
			inode->dirtied_when = jiffies;
	}
    //把inode移动到wb->b_dirty链表头，wb->b_dirty链表头的inode脏时间肯定是最新的，最大的
	list_move(&inode->i_wb_list, &wb->b_dirty);
}

/*
 * requeue inode for re-scanning after bdi->b_io list is exhausted.
 */
static void requeue_io(struct inode *inode, struct bdi_writeback *wb)
{
	assert_spin_locked(&wb->list_lock);
	list_move(&inode->i_wb_list, &wb->b_more_io);//把inode移动到到wb->b_more_io
}

static void inode_sync_complete(struct inode *inode)
{
	inode->i_state &= ~I_SYNC;
	/* If inode is clean an unused, put it into LRU now... */
	inode_add_lru(inode);
	/* Waiters must see I_SYNC cleared before being woken up */
	smp_mb();
	wake_up_bit(&inode->i_state, __I_SYNC);
}
//old_data_flush模式,inode脏时间>=30s返回false。background_flush模式只要inode是脏inode就返回false.
static bool inode_dirtied_after(struct inode *inode, unsigned long t)
{
    //old_data_flush模式，t=jiffes-30,如果inode的脏时间inode->dirtied_when > jiffes-30返回true，否则返回false。就是说，如果
    //inode脏时间>=30s返回false，inode脏时间<30s返回true。background_flush模式t=jiffes,只要inode脏时间<=jiffies返回false
	bool ret = time_after(inode->dirtied_when, t);
#ifndef CONFIG_64BIT
	/*
	 * For inodes being constantly redirtied, dirtied_when can get stuck.
	 * It _appears_ to be in the future, but is actually in distant past.
	 * This test is necessary to prevent such wrapped-around relative times
	 * from permanently stopping the whole bdi writeback.
	 */
	//这里我觉得成立可能性很低
	ret = ret && time_before_eq(inode->dirtied_when, jiffies);
#endif
	return ret;
}

/*
 * Move expired (dirtied before work->older_than_this) dirty inodes from
 * @delaying_queue to @dispatch_queue.
 */
static int move_expired_inodes(struct list_head *delaying_queue,//wb->b_dirty
			       struct list_head *dispatch_queue,//wb->b_io
			       struct wb_writeback_work *work)
{
	LIST_HEAD(tmp);
	struct list_head *pos, *node;
	struct super_block *sb = NULL;
	struct inode *inode;
	int do_sb_sort = 0;
	int moved = 0;

	while (!list_empty(delaying_queue)) {
		inode = wb_inode(delaying_queue->prev);
        //inode_dirtied_after():old_data_flush模式,inode脏时间>=30s返回false。background_flush模式只要inode是脏inode就返回false.
        //返回false，就把inode从wb->b_dirty链表移动到wb->b_io链表，然后就派发该inode
		if (work->older_than_this &&
		    inode_dirtied_after(inode, *work->older_than_this))
			break;
        //如果inode属于不同的超级快则do_sb_sort=1
		if (sb && sb != inode->i_sb)
			do_sb_sort = 1;
		sb = inode->i_sb;
        //把inode移动到tmp
		list_move(&inode->i_wb_list, &tmp);
        //每移动一个inode则moved加1
		moved++;
	}

	/* just one sb in list, splice to dispatch_queue and we're done */
    //如果inode都是一个超级快的，直接把inode移动到dispatch_queue链表
	if (!do_sb_sort) {
		list_splice(&tmp, dispatch_queue);
		goto out;
	}

	/* Move inodes from one superblock together */
    //如果inode属于不同的超级块，则把一个超级快的inode放到一块
	while (!list_empty(&tmp)) {
		sb = wb_inode(tmp.prev)->i_sb;
		list_for_each_prev_safe(pos, node, &tmp) {
			inode = wb_inode(pos);
            //属于同一个超级块的inode彼此挨着放到dispatch_queue链表
			if (inode->i_sb == sb)
				list_move(&inode->i_wb_list, dispatch_queue);
		}
	}
out:
	return moved;
}

/*
 * Queue all expired dirty inodes for io, eldest first.
 * Before
 *         newly dirtied     b_dirty    b_io    b_more_io
 *         =============>    gf         edc     BA
 * After
 *         newly dirtied     b_dirty    b_io    b_more_io
 *         =============>    g          fBAedc
 *                                           |
 *                                           +--> dequeue for IO
 */
//把wb->b_more_io或者wb->b_dirty上的dirty inode移动到wb->b_io
static void queue_io(struct bdi_writeback *wb, struct wb_writeback_work *work)
{
	int moved;
	assert_spin_locked(&wb->list_lock);
    //把wb->b_more_io上的dirty inode移动到wb->b_io
	list_splice_init(&wb->b_more_io, &wb->b_io);
    //把wb->b_dirty上的dirty inode移动到wb->b_io
	moved = move_expired_inodes(&wb->b_dirty, &wb->b_io, work);
	trace_writeback_queue_io(wb, work, moved);
}

static int write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int ret;

	if (inode->i_sb->s_op->write_inode && !is_bad_inode(inode)) {
		trace_writeback_write_inode_start(inode, wbc);
		ret = inode->i_sb->s_op->write_inode(inode, wbc);
		trace_writeback_write_inode(inode, wbc);
		return ret;
	}
	return 0;
}

/*
 * Wait for writeback on an inode to complete. Called with i_lock held.
 * Caller must make sure inode cannot go away when we drop i_lock.
 */
static void __inode_wait_for_writeback(struct inode *inode)
	__releases(inode->i_lock)
	__acquires(inode->i_lock)
{
	DEFINE_WAIT_BIT(wq, &inode->i_state, __I_SYNC);
	wait_queue_head_t *wqh;

	wqh = bit_waitqueue(&inode->i_state, __I_SYNC);
	while (inode->i_state & I_SYNC) {
		spin_unlock(&inode->i_lock);
		__wait_on_bit(wqh, &wq, inode_wait, TASK_UNINTERRUPTIBLE);
		spin_lock(&inode->i_lock);
	}
}

/*
 * Wait for writeback on an inode to complete. Caller must have inode pinned.
 */
void inode_wait_for_writeback(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	__inode_wait_for_writeback(inode);
	spin_unlock(&inode->i_lock);
}

/*
 * Sleep until I_SYNC is cleared. This function must be called with i_lock
 * held and drops it. It is aimed for callers not holding any inode reference
 * so once i_lock is dropped, inode can go away.
 */
static void inode_sleep_on_writeback(struct inode *inode)
	__releases(inode->i_lock)
{
	DEFINE_WAIT(wait);
	wait_queue_head_t *wqh = bit_waitqueue(&inode->i_state, __I_SYNC);
	int sleep;

	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	sleep = inode->i_state & I_SYNC;
	spin_unlock(&inode->i_lock);
	if (sleep)
		schedule();
	finish_wait(wqh, &wait);
}

/*
 * Find proper writeback list for the inode depending on its current state and
 * possibly also change of its state while we were doing writeback.  Here we
 * handle things such as livelock prevention or fairness of writeback among
 * inodes. This function can be called only by flusher thread - noone else
 * processes all inodes in writeback lists and requeueing inodes behind flusher
 * thread's back can have unexpected consequences.
 */
//如果inode还有脏页，把inode移动到到wb->b_more_io或者wb->b_dirty。inode没有脏数据则把inode从脏页链表清除掉
static void requeue_inode(struct inode *inode, struct bdi_writeback *wb,
			  struct writeback_control *wbc)
{
	if (inode->i_state & I_FREEING)
		return;

	/*
	 * Sync livelock prevention. Each inode is tagged and synced in one
	 * shot. If still dirty, it will be redirty_tail()'ed below.  Update
	 * the dirty time to prevent enqueue and sync it again.
	 */
	if ((inode->i_state & I_DIRTY) &&
	    (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages))
		inode->dirtied_when = jiffies;

	if (wbc->pages_skipped) {
		/*
		 * writeback is not making progress due to locked
		 * buffers. Skip this inode for now.
		 */
		redirty_tail(inode, wb);
		return;
	}
    //如果inode有脏数据page
	if (mapping_tagged(inode->i_mapping, PAGECACHE_TAG_DIRTY)) {
		/*
		 * We didn't write back all the pages.  nfs_writepages()
		 * sometimes bales out without doing anything.
		 */
		//wbc->nr_to_write <= 0 表示本次预期的脏数据已经刷回磁盘了，一般不成立吧
		if (wbc->nr_to_write <= 0) {
			/* Slice used up. Queue for next turn. */
            //把inode临时移动到wb->b_more_io，下次回写脏页再把b_more_io上的脏页移动到b_io
			requeue_io(inode, wb);
		} else {
			/*
			 * Writeback blocked by something other than
			 * congestion. Delay the inode for some time to
			 * avoid spinning on the CPU (100% iowait)
			 * retrying writeback of the dirty page/inode
			 * that cannot be performed immediately.
			 */
			//否则把inode移动到wb->b_dirty链表
			redirty_tail(inode, wb);
		}
	}
    else if (inode->i_state & I_DIRTY) {
		/*
		 * Filesystems can dirty the inode during writeback operations,
		 * such as delayed allocation during submission or metadata
		 * updates after data IO completion.
		 */
		//把inode移动到wb->b_dirty
		redirty_tail(inode, wb);
	} else {
		/* The inode is clean. Remove from writeback lists. */
        //inode没有脏数据，把inode从脏页链表wb->b_more_io或者wb->b_dirty清除掉
		list_del_init(&inode->i_wb_list);
	}
}

/*
 * Write out an inode and its dirty pages. Do not update the writeback list
 * linkage. That is left to the caller. The caller is also responsible for
 * setting I_SYNC flag and calling inode_sync_complete() to clear it.
 */
static int
__writeback_single_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct address_space *mapping = inode->i_mapping;
	long nr_to_write = wbc->nr_to_write;
	unsigned dirty;
	int ret;

	WARN_ON(!(inode->i_state & I_SYNC));

	trace_writeback_single_inode_start(inode, wbc, nr_to_write);

    //调用文件系统的接口把脏页数据回写到磁盘文件系统
	ret = do_writepages(mapping, wbc);

	/*
	 * Make sure to wait on the data before writing out the metadata.
	 * This is important for filesystems that modify metadata on data
	 * I/O completion.
	 */
	if (wbc->sync_mode == WB_SYNC_ALL) {
		int err = filemap_fdatawait(mapping);
		if (ret == 0)
			ret = err;
	}

	/*
	 * Some filesystems may redirty the inode during the writeback
	 * due to delalloc, clear dirty metadata flags right before
	 * write_inode()
	 */
	spin_lock(&inode->i_lock);
    //这里先把inode脏标记清除掉
	dirty = inode->i_state & I_DIRTY;
	inode->i_state &= ~I_DIRTY;

	/*
	 * Paired with smp_mb() in __mark_inode_dirty().  This allows
	 * __mark_inode_dirty() to test i_state without grabbing i_lock -
	 * either they see the I_DIRTY bits cleared or we see the dirtied
	 * inode.
	 *
	 * I_DIRTY_PAGES is always cleared together above even if @mapping
	 * still has dirty pages.  The flag is reinstated after smp_mb() if
	 * necessary.  This guarantees that either __mark_inode_dirty()
	 * sees clear I_DIRTY_PAGES or we see PAGECACHE_TAG_DIRTY.
	 */
	smp_mb();
    //如果inode还有脏页则再给inode加上I_DIRTY_PAGES标记
	if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		inode->i_state |= I_DIRTY_PAGES;

	spin_unlock(&inode->i_lock);

	/* Don't write the inode if only I_DIRTY_PAGES was set */
	if (dirty & (I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		int err = write_inode(inode, wbc);
		if (ret == 0)
			ret = err;
	}
	trace_writeback_single_inode(inode, wbc, nr_to_write);
	return ret;
}

/*
 * Write out an inode's dirty pages. Either the caller has an active reference
 * on the inode or the inode has I_WILL_FREE set.
 *
 * This function is designed to be called for writing back one inode which
 * we go e.g. from filesystem. Flusher thread uses __writeback_single_inode()
 * and does more profound writeback list handling in writeback_sb_inodes().
 */
static int
writeback_single_inode(struct inode *inode, struct bdi_writeback *wb,
		       struct writeback_control *wbc)
{
	int ret = 0;

	spin_lock(&inode->i_lock);
	if (!atomic_read(&inode->i_count))
		WARN_ON(!(inode->i_state & (I_WILL_FREE|I_FREEING)));
	else
		WARN_ON(inode->i_state & I_WILL_FREE);

	if (inode->i_state & I_SYNC) {
		if (wbc->sync_mode != WB_SYNC_ALL)
			goto out;
		/*
		 * It's a data-integrity sync. We must wait. Since callers hold
		 * inode reference or inode has I_WILL_FREE set, it cannot go
		 * away under us.
		 */
		__inode_wait_for_writeback(inode);
	}
	WARN_ON(inode->i_state & I_SYNC);
	/*
	 * Skip inode if it is clean and we have no outstanding writeback in
	 * WB_SYNC_ALL mode. We don't want to mess with writeback lists in this
	 * function since flusher thread may be doing for example sync in
	 * parallel and if we move the inode, it could get skipped. So here we
	 * make sure inode is on some writeback list and leave it there unless
	 * we have completely cleaned the inode.
	 */
	if (!(inode->i_state & I_DIRTY) &&
	    (wbc->sync_mode != WB_SYNC_ALL ||
	     !mapping_tagged(inode->i_mapping, PAGECACHE_TAG_WRITEBACK)))
		goto out;
	inode->i_state |= I_SYNC;
	spin_unlock(&inode->i_lock);

	ret = __writeback_single_inode(inode, wbc);

	spin_lock(&wb->list_lock);
	spin_lock(&inode->i_lock);
	/*
	 * If inode is clean, remove it from writeback lists. Otherwise don't
	 * touch it. See comment above for explanation.
	 */
	if (!(inode->i_state & I_DIRTY))
		list_del_init(&inode->i_wb_list);
	spin_unlock(&wb->list_lock);
	inode_sync_complete(inode);
out:
	spin_unlock(&inode->i_lock);
	return ret;
}

static long writeback_chunk_size(struct backing_dev_info *bdi,
				 struct wb_writeback_work *work)
{
	long pages;

	/*
	 * WB_SYNC_ALL mode does livelock avoidance by syncing dirty
	 * inodes/pages in one big loop. Setting wbc.nr_to_write=LONG_MAX
	 * here avoids calling into writeback_inodes_wb() more than once.
	 *
	 * The intended call sequence for WB_SYNC_ALL writeback is:
	 *
	 *      wb_writeback()
	 *          writeback_sb_inodes()       <== called only once
	 *              write_cache_pages()     <== called once for each inode
	 *                   (quickly) tag currently dirty pages
	 *                   (maybe slowly) sync all tagged pages
	 */
	if (work->sync_mode == WB_SYNC_ALL || work->tagged_writepages)
		pages = LONG_MAX;
	else {
		pages = min(bdi->avg_write_bandwidth / 2,
			    global_dirty_limit / DIRTY_SCOPE);
		pages = min(pages, work->nr_pages);
		pages = round_down(pages + MIN_WRITEBACK_PAGES,
				   MIN_WRITEBACK_PAGES);
	}

	return pages;
}

/*
 * Write a portion of b_io inodes which belong to @sb.
 *
 * Return the number of pages and/or inodes written.
 */
//从wb->b_io取出一个个脏inode，回写inode上的脏页，返回值是回写脏页数+回写完脏页的inode数
static long writeback_sb_inodes(struct super_block *sb,
				struct bdi_writeback *wb,
				struct wb_writeback_work *work)
{
	struct writeback_control wbc = {
		.sync_mode		= work->sync_mode,
		.tagged_writepages	= work->tagged_writepages,
		.for_kupdate		= work->for_kupdate,
		.for_background		= work->for_background,
		.range_cyclic		= work->range_cyclic,
		.range_start		= 0,
		.range_end		= LLONG_MAX,
	};
	unsigned long start_time = jiffies;
	long write_chunk;
	long wrote = 0;  /* count both pages and inodes */

	while (!list_empty(&wb->b_io)) {
        //从wb->b_io.prev取出有脏页的inode
		struct inode *inode = wb_inode(wb->b_io.prev);

        //这个if会成立吗?wb->b_io上的inode应该都是一个块设备里文件系统的inode，不应该成立吧????????????
		if (inode->i_sb != sb) {
			if (work->sb) {
				/*
				 * We only want to write back data for this
				 * superblock, move all inodes not belonging
				 * to it back onto the dirty list.
				 */
				redirty_tail(inode, wb);
				continue;
			}

			/*
			 * The inode belongs to a different superblock.
			 * Bounce back to the caller to unpin this and
			 * pin the next superblock.
			 */
			break;
		}

		/*
		 * Don't bother with new inodes or inodes being freed, first
		 * kind does not need periodic writeout yet, and for the latter
		 * kind writeout is handled by the freer.
		 */
		spin_lock(&inode->i_lock);
        //如果inode是I_NEW状态，或者inode对应文件关闭正在释放文件数据
		if (inode->i_state & (I_NEW | I_FREEING | I_WILL_FREE)) {
			spin_unlock(&inode->i_lock);
            //把inode移动到wb->b_dirty
			redirty_tail(inode, wb);
			continue;
		}
        //如果inode的脏页在回写，并且是wb_check_old_data_flush和wb_check_background_flush发起的脏页回写
		if ((inode->i_state & I_SYNC) && wbc.sync_mode != WB_SYNC_ALL) {
			/*
			 * If this inode is locked for writeback and we are not
			 * doing writeback-for-data-integrity, move it to
			 * b_more_io so that writeback can proceed with the
			 * other inodes on s_io.
			 *
			 * We'll have another go at writing back this inode
			 * when we completed a full scan of b_io.
			 */
			spin_unlock(&inode->i_lock);
			requeue_io(inode, wb);//把inode->i_wb_list移动到到wb->b_more_io
			trace_writeback_sb_inodes_requeue(inode);
			continue;
		}
		spin_unlock(&wb->list_lock);

		/*
		 * We already requeued the inode if it had I_SYNC set and we
		 * are doing WB_SYNC_NONE writeback. So this catches only the
		 * WB_SYNC_ALL case.
		 */
		//如果inode的脏数据在同步到磁盘，先休眠
		if (inode->i_state & I_SYNC) {
			/* Wait for I_SYNC. This function drops i_lock... */
			inode_sleep_on_writeback(inode);
			/* Inode may be gone, start again */
			spin_lock(&wb->list_lock);
			continue;
		}
        //inode->i_state设置I_SYNC标记
		inode->i_state |= I_SYNC;
		spin_unlock(&inode->i_lock);

        //计算本次预期回收page数
		write_chunk = writeback_chunk_size(wb->bdi, work);
        //wbc.nr_to_write初值是本次预期回收page数
		wbc.nr_to_write = write_chunk;
		wbc.pages_skipped = 0;

		/*
		 * We use I_SYNC to pin the inode in memory. While it is set
		 * evict_inode() will wait so the inode cannot be freed.
		 */
		__writeback_single_inode(inode, &wbc);//这里真正回刷脏页

        //write_chunk是本次循环预期回收的page数，wbc.nr_to_write是还剩下的待回写的page数，相减就是已经回写的脏页数
		work->nr_pages -= write_chunk - wbc.nr_to_write;
		wrote += write_chunk - wbc.nr_to_write;//wrote累计回刷的page总数
		spin_lock(&wb->list_lock);
		spin_lock(&inode->i_lock);

        //如果inode的脏页回写完成了，wrote还要加1
		if (!(inode->i_state & I_DIRTY))
			wrote++;
        
        //如果inode还有脏页，把inode移动到到wb->b_more_io或者wb->b_dirty。如果inode没有脏数据则把inode从脏页链表清除掉
		requeue_inode(inode, wb, &wbc);
        
        //清除I_SYNC，wake_up_bit(&inode->i_state, __I_SYNC)
		inode_sync_complete(inode);
		spin_unlock(&inode->i_lock);
		cond_resched_lock(&wb->list_lock);
		/*
		 * bail out to wb_writeback() often enough to check
		 * background threshold and other termination conditions.
		 */
		if (wrote) {
            //HZ/10=100，就是100ms，jiffes>start_time+100返回true，最大回刷时间100ms，为了避免长时间回刷脏数据影响其他进程
			if (time_is_before_jiffies(start_time + HZ / 10UL))
				break;
			if (work->nr_pages <= 0)
				break;
		}
	}

    //这里的返回值wrote是回写脏page数+回写完脏页的inode数
	return wrote;
}

static long __writeback_inodes_wb(struct bdi_writeback *wb,
				  struct wb_writeback_work *work)
{
	unsigned long start_time = jiffies;
	long wrote = 0;

	while (!list_empty(&wb->b_io)) {
		struct inode *inode = wb_inode(wb->b_io.prev);
        //取出wb->b_io链表第一个inode的的超级快
		struct super_block *sb = inode->i_sb;

		if (!grab_super_passive(sb)) {
			/*
			 * grab_super_passive() may fail consistently due to
			 * s_umount being grabbed by someone else. Don't use
			 * requeue_io() to avoid busy retrying the inode/sb.
			 */
			redirty_tail(inode, wb);
			continue;
		}
        
		wrote += writeback_sb_inodes(sb, wb, work);
		drop_super(sb);

		/* refer to the same tests at the end of writeback_sb_inodes */
		if (wrote) {
            //HZ/10=100，就是100ms，jiffes>start_time+100返回true，最大回刷时间100ms，为了避免长时间回刷脏数据影响其他进程
			if (time_is_before_jiffies(start_time + HZ / 10UL))
				break;
            
            //work->nr_pages初值是LONG_MAX，基本不可能成立
			if (work->nr_pages <= 0)
				break;
		}
	}
	/* Leave any unwritten inodes on b_io */
    
    //返回值是回写脏页数+回写完脏页的inode数
	return wrote;
}

long writeback_inodes_wb(struct bdi_writeback *wb, long nr_pages,
				enum wb_reason reason)
{
	struct wb_writeback_work work = {
		.nr_pages	= nr_pages,
		.sync_mode	= WB_SYNC_NONE,
		.range_cyclic	= 1,
		.reason		= reason,
	};

	spin_lock(&wb->list_lock);
	if (list_empty(&wb->b_io))
		queue_io(wb, &work);
	__writeback_inodes_wb(wb, &work);
	spin_unlock(&wb->list_lock);

	return nr_pages - work.nr_pages;
}

static bool over_bground_thresh(struct backing_dev_info *bdi)
{
	unsigned long background_thresh, dirty_thresh;

	global_dirty_limits(&background_thresh, &dirty_thresh);

	if (global_page_state(NR_FILE_DIRTY) +
	    global_page_state(NR_UNSTABLE_NFS) > background_thresh)
		return true;

	if (bdi_stat(bdi, BDI_RECLAIMABLE) >
				bdi_dirty_limit(bdi, background_thresh))
		return true;

	return false;
}

/*
 * Called under wb->list_lock. If there are multiple wb per bdi,
 * only the flusher working on the first wb should do it.
 */
static void wb_update_bandwidth(struct bdi_writeback *wb,
				unsigned long start_time)
{
	__bdi_update_bandwidth(wb->bdi, 0, 0, 0, 0, 0, start_time);
}

/*
 * Explicit flushing or periodic writeback of "old" data.
 *
 * Define "old": the first time one of an inode's pages is dirtied, we mark the
 * dirtying-time in the inode's address_space.  So this periodic writeback code
 * just walks the superblock inode list, writing back any inodes which are
 * older than a specific point in time.
 *
 * Try to run once per dirty_writeback_interval.  But if a writeback event
 * takes longer than a dirty_writeback_interval interval, then leave a
 * one-second gap.
 *
 * older_than_this takes precedence over nr_to_write.  So we'll only write back
 * all dirty pages if they are all attached to "old" mappings.
 */
//回刷脏数据的核心入口函数，返回值是回刷的脏页总数，不包含回写完脏页的inode数
static long wb_writeback(struct bdi_writeback *wb,
			 struct wb_writeback_work *work)
{
	unsigned long wb_start = jiffies;
	long nr_pages = work->nr_pages;
	unsigned long oldest_jif;
	struct inode *inode;
	long progress;

	oldest_jif = jiffies;
    //work->older_than_this指向局部变量oldest_jif
	work->older_than_this = &oldest_jif;

	spin_lock(&wb->list_lock);
	for (;;) {
		/*
		 * Stop writeback when nr_pages has been consumed
		 */
		//回写藏页数达到预期则brask
		if (work->nr_pages <= 0)
			break;

		/*
		 * Background writeout and kupdate-style writeback may
		 * run forever. Stop them if there is other work to do
		 * so that e.g. sync can proceed. They'll be restarted
		 * after the other works are all done.
		 */
		if ((work->for_background || work->for_kupdate) &&
		    !list_empty(&wb->bdi->work_list))
			break;

		/*
		 * For background writeout, stop when we are below the
		 * background dirty threshold
		 */
		//background_flush模式work->for_background是1，这里是判断脏页总数超过阀值则停止回写脏页
		if (work->for_background && !over_bground_thresh(wb->bdi))
			break;

		/*
		 * Kupdate and background works are special and we want to
		 * include all inodes that need writing. Livelock avoidance is
		 * handled by these works yielding to any other work so we are
		 * safe.
		 */
		//old_data_flush回写历史脏页模式，oldest_jif表示的时间是30s前，work->older_than_this指向它，下边的queue_io()函数会用
		//oldest_jif来判断一个脏inode是否脏了30s，超过了30s就要回写该inode上的脏页
		if (work->for_kupdate) {
			oldest_jif = jiffies -
				msecs_to_jiffies(dirty_expire_interval * 10);
        //background_flush超过脏页阀值则回写脏页模式，oldest_jif赋值当前时间，表示只要是inode脏了，不管脏了多久，都回写它的脏页
		} else if (work->for_background)
			oldest_jif = jiffies;

		trace_writeback_start(wb->bdi, work);
        
        //如果wb->b_io空，把wb->b_more_io或者wb->b_dirty上的dirty inode移动到wb->b_io
		if (list_empty(&wb->b_io))
			queue_io(wb, work);
        
		if (work->sb)//正常回写脏页一般不走这里，但是也有抓到走这里
			progress = writeback_sb_inodes(work->sb, wb, work);
		else//从wb->b_io链表取出一个个脏inode，回刷inode的脏数据，返回值是回刷的脏页数+脏页回写完的inode数
			progress = __writeback_inodes_wb(wb, work);
		trace_writeback_written(wb->bdi, work);

		wb_update_bandwidth(wb, wb_start);

		/*
		 * Did we write something? Try for more
		 *
		 * Dirty inodes are moved to b_io for writeback in batches.
		 * The completion of the current batch does not necessarily
		 * mean the overall work is done. So we keep looping as long
		 * as made some progress on cleaning pages or inodes.
		 */
		//实际测试下来progress大部分情况大于0。如果回写脏页数是0，progress就是0
		if (progress)
			continue;
		/*
		 * No more inodes for IO, bail
		 */
		//b_more_io保存临时没来得及传输的inode，没有inode则break结束回写脏页
		if (list_empty(&wb->b_more_io))
			break;
		/*
		 * Nothing written. Wait for some inode to
		 * become available for writeback. Otherwise
		 * we'll just busyloop.
		 */
		if (!list_empty(&wb->b_more_io))  {
			trace_writeback_wait(wb->bdi, work);
            //从wb->b_more_io取出inode
			inode = wb_inode(wb->b_more_io.prev);
			spin_lock(&inode->i_lock);
			spin_unlock(&wb->list_lock);
			/* This function drops i_lock... */
            //休眠等待inode脏页回写完成
			inode_sleep_on_writeback(inode);
			spin_lock(&wb->list_lock);
		}
	}
	spin_unlock(&wb->list_lock);
    
    //返回值是回刷的脏页总数，不包含回写完脏页的inode数，与__writeback_inodes_wb()和writeback_sb_inodes()的返回值不一样
	return nr_pages - work->nr_pages;
}

/*
 * Return the next wb_writeback_work struct that hasn't been processed yet.
 */
static struct wb_writeback_work *
get_next_work_item(struct backing_dev_info *bdi)
{
	struct wb_writeback_work *work = NULL;

	spin_lock_bh(&bdi->wb_lock);
	if (!list_empty(&bdi->work_list)) {
		work = list_entry(bdi->work_list.next,
				  struct wb_writeback_work, list);
		list_del_init(&work->list);
	}
	spin_unlock_bh(&bdi->wb_lock);
	return work;
}

/*
 * Add in the number of potentially dirty inodes, because each inode
 * write can dirty pagecache in the underlying blockdev.
 */
//获取脏页数，来自NR_FILE_DIRTY+NR_UNSTABLE_NFS+ dirty inodes
static unsigned long get_nr_dirty_pages(void)
{
	return global_page_state(NR_FILE_DIRTY) +
		global_page_state(NR_UNSTABLE_NFS) +
		get_nr_dirty_inodes();
}
//脏页超过阀值则执行wb_writeback()回刷脏页
static long wb_check_background_flush(struct bdi_writeback *wb)
{
    //脏页超过阀值返回true
	if (over_bground_thresh(wb->bdi)) {

		struct wb_writeback_work work = {
			.nr_pages	= LONG_MAX,
			.sync_mode	= WB_SYNC_NONE,
			.for_background	= 1,
			.range_cyclic	= 1,
			.reason		= WB_REASON_BACKGROUND,
		};
        //回写脏页，返回值是回刷的脏页总数，不包含回写完脏页的inode数
		return wb_writeback(wb, &work);
	}

	return 0;
}
//每间隔5s，如果有脏页，则执行wb_writeback()回刷脏页
static long wb_check_old_data_flush(struct bdi_writeback *wb)
{
	unsigned long expired;
	long nr_pages;

	/*
	 * When set to zero, disable periodic writeback
	 */
	if (!dirty_writeback_interval)
		return 0;

	expired = wb->last_old_flush +
			msecs_to_jiffies(dirty_writeback_interval * 10);//dirty_writeback_interval默认5s
			
	//每两次执行该函数的时间差大于dirty_writeback_interval，才会继续执行，保证脏页回写进程5s定执行一次
	if (time_before(jiffies, expired))//jiffies<expired返回true
		return 0;

	wb->last_old_flush = jiffies;
    //获取脏页数，来自nr_pages=NR_FILE_DIRTY+NR_UNSTABLE_NFS+ dirty inodes，竟然包含脏inode个数
	nr_pages = get_nr_dirty_pages();
    //如果还有脏页继续执行wb_writeback()刷脏页
	if (nr_pages) {
		struct wb_writeback_work work = {
			.nr_pages	= nr_pages,
			.sync_mode	= WB_SYNC_NONE,
			.for_kupdate	= 1,
			.range_cyclic	= 1,
			.reason		= WB_REASON_PERIODIC,
		};
        //回写脏页，返回值是回刷的脏页总数，不包含回写完脏页的inode数
		return wb_writeback(wb, &work);
	}

	return 0;
}

/*
 * Retrieve work items and do the writeback they describe
 */
long wb_do_writeback(struct bdi_writeback *wb, int force_wait)
{
	struct backing_dev_info *bdi = wb->bdi;
	struct wb_writeback_work *work;
	long wrote = 0;

	set_bit(BDI_writeback_running, &wb->bdi->state);
    
    //从bdi->work_list取出work，然后剔除掉work，正常回写脏页这里不成立，可能是块设备初始化
	while ((work = get_next_work_item(bdi)) != NULL) {
		/*
		 * Override sync mode, in case we must wait for completion
		 * because this thread is exiting now.
		 */
		if (force_wait)
			work->sync_mode = WB_SYNC_ALL;

		trace_writeback_exec(bdi, work);

		wrote += wb_writeback(wb, work);//这个实际测试没有执行到

		/*
		 * Notify the caller of completion if this is a synchronous
		 * work item, otherwise just free it.
		 */
		if (work->done)
			complete(work->done);
		else
			kfree(work);
	}

	/*
	 * Check for periodic writeback, kupdated() style
	 */
	//回写历史脏数据，脏页30s回写就是在这里
	wrote += wb_check_old_data_flush(wb);
    //脏页数超过阈值则回写脏页走这里
	wrote += wb_check_background_flush(wb);
	clear_bit(BDI_writeback_running, &wb->bdi->state);

    //返回值回写的脏页总数
	return wrote;
}

/*
 * Handle writeback of dirty data for the device backed by this bdi. Also
 * reschedules periodically and does kupdated style flushing.
 */
void bdi_writeback_workfn(struct work_struct *work)
{
    //先通过struct work_struct *work 找到struct delayed_work，再通过struct delayed_work container_of找到struct bdi_writeback
	struct bdi_writeback *wb = container_of(to_delayed_work(work),
						struct bdi_writeback, dwork);
	struct backing_dev_info *bdi = wb->bdi;
	long pages_written;

	set_worker_desc("flush-%s", dev_name(bdi->dev));
	current->flags |= PF_SWAPWRITE;

	if (likely(!current_is_workqueue_rescuer() ||
		   !test_bit(BDI_registered, &bdi->state))) {
		/*
		 * The normal path.  Keep writing back @bdi until its
		 * work_list is empty.  Note that this path is also taken
		 * if @bdi is shutting down even when we're running off the
		 * rescuer as work_list needs to be drained.
		 */
		do {
            //回写脏页，返回值回写的脏页总数
			pages_written = wb_do_writeback(wb, 0);
			trace_writeback_pages_written(pages_written);
		} while (!list_empty(&bdi->work_list));
	} else {
		/*
		 * bdi_wq can't get enough workers and we're running off
		 * the emergency worker.  Don't hog it.  Hopefully, 1024 is
		 * enough for efficient IO.
		 */
		pages_written = writeback_inodes_wb(&bdi->wb, 1024,
						    WB_REASON_FORKER_THREAD);
		trace_writeback_pages_written(pages_written);
	}

	if (!list_empty(&bdi->work_list))
		mod_delayed_work(bdi_wq, &wb->dwork, 0);//这应该是work_list链表有work，立即把work加入队列，立即执行
	else if (wb_has_dirty_io(wb) && dirty_writeback_interval)
        //否则，定时5s后，把bdi->wb.dwork加入到bdi_wq，之后脏页回写进程很快取出该dwork，再次执行bdi_writeback_workfn()函数
		bdi_wakeup_thread_delayed(bdi);

	current->flags &= ~PF_SWAPWRITE;
}

/*
 * Start writeback of `nr_pages' pages.  If `nr_pages' is zero, write back
 * the whole world.
 */
void wakeup_flusher_threads(long nr_pages, enum wb_reason reason)
{
	struct backing_dev_info *bdi;

	if (!nr_pages) {
		nr_pages = global_page_state(NR_FILE_DIRTY) +
				global_page_state(NR_UNSTABLE_NFS);
	}

	rcu_read_lock();
	list_for_each_entry_rcu(bdi, &bdi_list, bdi_list) {
		if (!bdi_has_dirty_io(bdi))
			continue;
		__bdi_start_writeback(bdi, nr_pages, false, reason);
	}
	rcu_read_unlock();
}

static noinline void block_dump___mark_inode_dirty(struct inode *inode)
{
	if (inode->i_ino || strcmp(inode->i_sb->s_id, "bdev")) {
		struct dentry *dentry;
		const char *name = "?";

		dentry = d_find_alias(inode);
		if (dentry) {
			spin_lock(&dentry->d_lock);
			name = (const char *) dentry->d_name.name;
		}
		printk(KERN_DEBUG
		       "%s(%d): dirtied inode %lu (%s) on %s\n",
		       current->comm, task_pid_nr(current), inode->i_ino,
		       name, inode->i_sb->s_id);
		if (dentry) {
			spin_unlock(&dentry->d_lock);
			dput(dentry);
		}
	}
}

/**
 *	__mark_inode_dirty -	internal function
 *	@inode: inode to mark
 *	@flags: what kind of dirty (i.e. I_DIRTY_SYNC)
 *	Mark an inode as dirty. Callers should use mark_inode_dirty or
 *  	mark_inode_dirty_sync.
 *
 * Put the inode on the super block's dirty list.
 *
 * CAREFUL! We mark it dirty unconditionally, but move it onto the
 * dirty list only if it is hashed or if it refers to a blockdev.
 * If it was not hashed, it will never be added to the dirty list
 * even if it is later hashed, as it will have been marked dirty already.
 *
 * In short, make sure you hash any inodes _before_ you start marking
 * them dirty.
 *
 * Note that for blockdevs, inode->dirtied_when represents the dirtying time of
 * the block-special inode (/dev/hda1) itself.  And the ->dirtied_when field of
 * the kernel-internal blockdev inode represents the dirtying time of the
 * blockdev's pages.  This is why for I_DIRTY_PAGES we always use
 * page->mapping->host, so the page-dirtying time is recorded in the internal
 * blockdev inode.
 */
void __mark_inode_dirty(struct inode *inode, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct backing_dev_info *bdi = NULL;

	/*
	 * Don't do this for I_DIRTY_PAGES - that doesn't actually
	 * dirty the inode itself
	 */
	if (flags & (I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		trace_writeback_dirty_inode_start(inode, flags);

		if (sb->s_op->dirty_inode)
			sb->s_op->dirty_inode(inode, flags);

		trace_writeback_dirty_inode(inode, flags);
	}

	/*
	 * Paired with smp_mb() in __writeback_single_inode() for the
	 * following lockless i_state test.  See there for details.
	 */
	smp_mb();
    //如果重复设置inode->i_state同一个状态则直接返回。如果一个inode连续设置I_DIRTY或者I_DIRTY_PAGES，在这里直接return
	if ((inode->i_state & flags) == flags)
		return;

	if (unlikely(block_dump))
		block_dump___mark_inode_dirty(inode);

	spin_lock(&inode->i_lock);
	if ((inode->i_state & flags) != flags) {
        //inode之前是否已经设置脏标记
		const int was_dirty = inode->i_state & I_DIRTY;//I_DIRTY: bit0、bit1、bit2 置1

		inode->i_state |= flags;

		/*
		 * If the inode is being synced, just update its dirty state.
		 * The unlocker will place the inode on the appropriate
		 * superblock list, based upon its state.
		 */
		if (inode->i_state & I_SYNC)//bit7置1
			goto out_unlock_inode;

		/*
		 * Only add valid (hashed) inodes to the superblock's
		 * dirty list.  Add blockdev inodes as well.
		 */
		if (!S_ISBLK(inode->i_mode)) {
			if (inode_unhashed(inode))
				goto out_unlock_inode;
		}
		if (inode->i_state & I_FREEING)//bit5置1
			goto out_unlock_inode;

		/*
		 * If the inode was already on b_dirty/b_io/b_more_io, don't
		 * reposition it (that would break b_dirty time-ordering).
		 */
		//如果inode已经标记过脏,if不成立。
		//里边有3个重要操作，更新inode脏时间、把inode加入wb.b_dirty链表、如果块设备wb原本没有脏页则把dwork插入到bdi_wq队列，唤醒脏页回写进程
		if (!was_dirty) {
			bool wakeup_bdi = false;
            //返回inode对应文件所在块设备的backing_dev_info结构
			bdi = inode_to_bdi(inode);

			if (bdi_cap_writeback_dirty(bdi)) {
				WARN(!test_bit(BDI_registered, &bdi->state),
				     "bdi-%s not registered\n", bdi->name);

				/*
				 * If this is the first dirty inode for this
				 * bdi, we have to wake-up the corresponding
				 * bdi thread to make sure background
				 * write-back happens later.
				 */
				//如果块设备wb->b_io、wb->b_dirty、wb->b_more_io链表上已经有脏inode，则if不成立，
				if (!wb_has_dirty_io(&bdi->wb))
					wakeup_bdi = true;
			}

			spin_unlock(&inode->i_lock);
			spin_lock(&bdi->wb.list_lock);
            //1:更新inode脏时间
			inode->dirtied_when = jiffies;
            //2:把dirty inode启动到bdi->wb.b_dirty
			list_move(&inode->i_wb_list, &bdi->wb.b_dirty);
			spin_unlock(&bdi->wb.list_lock);

            //3:如果块设备没有脏页，把bdi->wb.dwork加入到bdi_wq队列，定时5s执行该work，work对应线程就是刷脏数据的内核kworker/u..进程
			if (wakeup_bdi)
				bdi_wakeup_thread_delayed(bdi);
			return;
		}
	}
out_unlock_inode:
	spin_unlock(&inode->i_lock);

}
EXPORT_SYMBOL(__mark_inode_dirty);

static void wait_sb_inodes(struct super_block *sb)
{
	struct inode *inode, *old_inode = NULL;

	/*
	 * We need to be protected against the filesystem going from
	 * r/o to r/w or vice versa.
	 */
	WARN_ON(!rwsem_is_locked(&sb->s_umount));

	spin_lock(&inode_sb_list_lock);

	/*
	 * Data integrity sync. Must wait for all pages under writeback,
	 * because there may have been pages dirtied before our sync
	 * call, but which had writeout started before we write it out.
	 * In which case, the inode may not be on the dirty list, but
	 * we still have to wait for that writeout.
	 */
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		struct address_space *mapping = inode->i_mapping;

		spin_lock(&inode->i_lock);
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (mapping->nrpages == 0)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&inode_sb_list_lock);

		/*
		 * We hold a reference to 'inode' so it couldn't have been
		 * removed from s_inodes list while we dropped the
		 * inode_sb_list_lock.  We cannot iput the inode now as we can
		 * be holding the last reference and we cannot iput it under
		 * inode_sb_list_lock. So we keep the reference and iput it
		 * later.
		 */
		iput(old_inode);
		old_inode = inode;

		filemap_fdatawait(mapping);

		cond_resched();

		spin_lock(&inode_sb_list_lock);
	}
	spin_unlock(&inode_sb_list_lock);
	iput(old_inode);
}

/**
 * writeback_inodes_sb_nr -	writeback dirty inodes from given super_block
 * @sb: the superblock
 * @nr: the number of pages to write
 * @reason: reason why some writeback work initiated
 *
 * Start writeback on some inodes on this super_block. No guarantees are made
 * on how many (if any) will be written, and this function does not wait
 * for IO completion of submitted IO.
 */
void writeback_inodes_sb_nr(struct super_block *sb,
			    unsigned long nr,
			    enum wb_reason reason)
{
	DECLARE_COMPLETION_ONSTACK(done);
	struct wb_writeback_work work = {
		.sb			= sb,
		.sync_mode		= WB_SYNC_NONE,
		.tagged_writepages	= 1,
		.done			= &done,
		.nr_pages		= nr,
		.reason			= reason,
	};

	if (sb->s_bdi == &noop_backing_dev_info)
		return;
	WARN_ON(!rwsem_is_locked(&sb->s_umount));
	bdi_queue_work(sb->s_bdi, &work);
	wait_for_completion(&done);
}
EXPORT_SYMBOL(writeback_inodes_sb_nr);

/**
 * writeback_inodes_sb	-	writeback dirty inodes from given super_block
 * @sb: the superblock
 * @reason: reason why some writeback work was initiated
 *
 * Start writeback on some inodes on this super_block. No guarantees are made
 * on how many (if any) will be written, and this function does not wait
 * for IO completion of submitted IO.
 */
void writeback_inodes_sb(struct super_block *sb, enum wb_reason reason)
{
	return writeback_inodes_sb_nr(sb, get_nr_dirty_pages(), reason);
}
EXPORT_SYMBOL(writeback_inodes_sb);

/**
 * try_to_writeback_inodes_sb_nr - try to start writeback if none underway
 * @sb: the superblock
 * @nr: the number of pages to write
 * @reason: the reason of writeback
 *
 * Invoke writeback_inodes_sb_nr if no writeback is currently underway.
 * Returns 1 if writeback was started, 0 if not.
 */
int try_to_writeback_inodes_sb_nr(struct super_block *sb,
				  unsigned long nr,
				  enum wb_reason reason)
{
	if (writeback_in_progress(sb->s_bdi))
		return 1;

	if (!down_read_trylock(&sb->s_umount))
		return 0;

	writeback_inodes_sb_nr(sb, nr, reason);
	up_read(&sb->s_umount);
	return 1;
}
EXPORT_SYMBOL(try_to_writeback_inodes_sb_nr);

/**
 * try_to_writeback_inodes_sb - try to start writeback if none underway
 * @sb: the superblock
 * @reason: reason why some writeback work was initiated
 *
 * Implement by try_to_writeback_inodes_sb_nr()
 * Returns 1 if writeback was started, 0 if not.
 */
int try_to_writeback_inodes_sb(struct super_block *sb, enum wb_reason reason)
{
	return try_to_writeback_inodes_sb_nr(sb, get_nr_dirty_pages(), reason);
}
EXPORT_SYMBOL(try_to_writeback_inodes_sb);

/**
 * sync_inodes_sb	-	sync sb inode pages
 * @sb: the superblock
 *
 * This function writes and waits on any dirty inode belonging to this
 * super_block.
 */
void sync_inodes_sb(struct super_block *sb)
{
	DECLARE_COMPLETION_ONSTACK(done);
	struct wb_writeback_work work = {
		.sb		= sb,
		.sync_mode	= WB_SYNC_ALL,
		.nr_pages	= LONG_MAX,
		.range_cyclic	= 0,
		.done		= &done,
		.reason		= WB_REASON_SYNC,
	};

	/* Nothing to do? */
	if (sb->s_bdi == &noop_backing_dev_info)
		return;
	WARN_ON(!rwsem_is_locked(&sb->s_umount));

	bdi_queue_work(sb->s_bdi, &work);
	wait_for_completion(&done);

	wait_sb_inodes(sb);
}
EXPORT_SYMBOL(sync_inodes_sb);

/**
 * write_inode_now	-	write an inode to disk
 * @inode: inode to write to disk
 * @sync: whether the write should be synchronous or not
 *
 * This function commits an inode to disk immediately if it is dirty. This is
 * primarily needed by knfsd.
 *
 * The caller must either have a ref on the inode or must have set I_WILL_FREE.
 */
int write_inode_now(struct inode *inode, int sync)
{
	struct bdi_writeback *wb = &inode_to_bdi(inode)->wb;
	struct writeback_control wbc = {
		.nr_to_write = LONG_MAX,
		.sync_mode = sync ? WB_SYNC_ALL : WB_SYNC_NONE,
		.range_start = 0,
		.range_end = LLONG_MAX,
	};

	if (!mapping_cap_writeback_dirty(inode->i_mapping))
		wbc.nr_to_write = 0;

	might_sleep();
	return writeback_single_inode(inode, wb, &wbc);
}
EXPORT_SYMBOL(write_inode_now);

/**
 * sync_inode - write an inode and its pages to disk.
 * @inode: the inode to sync
 * @wbc: controls the writeback mode
 *
 * sync_inode() will write an inode and its pages to disk.  It will also
 * correctly update the inode on its superblock's dirty inode lists and will
 * update inode->i_state.
 *
 * The caller must have a ref on the inode.
 */
int sync_inode(struct inode *inode, struct writeback_control *wbc)
{
	return writeback_single_inode(inode, &inode_to_bdi(inode)->wb, wbc);
}
EXPORT_SYMBOL(sync_inode);

/**
 * sync_inode_metadata - write an inode to disk
 * @inode: the inode to sync
 * @wait: wait for I/O to complete.
 *
 * Write an inode to disk and adjust its dirty state after completion.
 *
 * Note: only writes the actual inode, no associated data or other metadata.
 */
int sync_inode_metadata(struct inode *inode, int wait)
{
	struct writeback_control wbc = {
		.sync_mode = wait ? WB_SYNC_ALL : WB_SYNC_NONE,
		.nr_to_write = 0, /* metadata-only */
	};

	return sync_inode(inode, &wbc);
}
EXPORT_SYMBOL(sync_inode_metadata);
