/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the operation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * Documentation/sysctl/vm.txt.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/mm_inline.h>
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/backing-dev.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/uio.h>
#include <linux/hugetlb.h>

#include "internal.h"

/* How many pages do we try to swap or page in/out together? */
int page_cluster;

static DEFINE_PER_CPU(struct pagevec[NR_LRU_LISTS], lru_add_pvecs);//新的page先添加到lru_add_pvecs，见__lru_cache_add()
static DEFINE_PER_CPU(struct pagevec, lru_rotate_pvecs);//该链表page添加到inactive lru链表尾，见rotate_reclaimable_page()
static DEFINE_PER_CPU(struct pagevec, lru_deactivate_pvecs);//见deactivate_page(),该链表page添加到inactive lru链表头

/*
 * This path almost never happens for VM activity - pages are normally
 * freed via pagevecs.  But it gets used by networking.
 */
static void __page_cache_release(struct page *page)
{
	if (PageLRU(page)) {
		struct zone *zone = page_zone(page);
		struct lruvec *lruvec;
		unsigned long flags;

		spin_lock_irqsave(&zone->lru_lock, flags);
		lruvec = mem_cgroup_page_lruvec(page, zone);
		VM_BUG_ON(!PageLRU(page));
		__ClearPageLRU(page);
		del_page_from_lru_list(page, lruvec, page_off_lru(page));
		spin_unlock_irqrestore(&zone->lru_lock, flags);
	}
}

static void __put_single_page(struct page *page)
{
	__page_cache_release(page);
	free_hot_cold_page(page, 0);
}

static void __put_compound_page(struct page *page)
{
	compound_page_dtor *dtor;

	__page_cache_release(page);
	dtor = get_compound_page_dtor(page);
	(*dtor)(page);
}

static void put_compound_page(struct page *page)
{
	if (unlikely(PageTail(page))) {
		/* __split_huge_page_refcount can run under us */
		struct page *page_head = compound_head(page);

		if (likely(page != page_head &&
			   get_page_unless_zero(page_head))) {
			unsigned long flags;

			/*
			 * THP can not break up slab pages so avoid taking
			 * compound_lock().  Slab performs non-atomic bit ops
			 * on page->flags for better performance.  In particular
			 * slab_unlock() in slub used to be a hot path.  It is
			 * still hot on arches that do not support
			 * this_cpu_cmpxchg_double().
			 */
			if (PageSlab(page_head) || PageHeadHuge(page_head)) {
				if (likely(PageTail(page))) {
					/*
					 * __split_huge_page_refcount
					 * cannot race here.
					 */
					VM_BUG_ON(!PageHead(page_head));
					atomic_dec(&page->_mapcount);
					if (put_page_testzero(page_head))
						VM_BUG_ON(1);
					if (put_page_testzero(page_head))
						__put_compound_page(page_head);
					return;
				} else
					/*
					 * __split_huge_page_refcount
					 * run before us, "page" was a
					 * THP tail. The split
					 * page_head has been freed
					 * and reallocated as slab or
					 * hugetlbfs page of smaller
					 * order (only possible if
					 * reallocated as slab on
					 * x86).
					 */
					goto skip_lock;
			}
			/*
			 * page_head wasn't a dangling pointer but it
			 * may not be a head page anymore by the time
			 * we obtain the lock. That is ok as long as it
			 * can't be freed from under us.
			 */
			flags = compound_lock_irqsave(page_head);
			if (unlikely(!PageTail(page))) {
				/* __split_huge_page_refcount run before us */
				compound_unlock_irqrestore(page_head, flags);
skip_lock:
				if (put_page_testzero(page_head)) {
					/*
					 * The head page may have been
					 * freed and reallocated as a
					 * compound page of smaller
					 * order and then freed again.
					 * All we know is that it
					 * cannot have become: a THP
					 * page, a compound page of
					 * higher order, a tail page.
					 * That is because we still
					 * hold the refcount of the
					 * split THP tail and
					 * page_head was the THP head
					 * before the split.
					 */
					if (PageHead(page_head))
						__put_compound_page(page_head);
					else
						__put_single_page(page_head);
				}
out_put_single:
				if (put_page_testzero(page))
					__put_single_page(page);
				return;
			}
			VM_BUG_ON(page_head != page->first_page);
			/*
			 * We can release the refcount taken by
			 * get_page_unless_zero() now that
			 * __split_huge_page_refcount() is blocked on
			 * the compound_lock.
			 */
			if (put_page_testzero(page_head))
				VM_BUG_ON(1);
			/* __split_huge_page_refcount will wait now */
			VM_BUG_ON(page_mapcount(page) <= 0);
			atomic_dec(&page->_mapcount);
			VM_BUG_ON(atomic_read(&page_head->_count) <= 0);
			VM_BUG_ON(atomic_read(&page->_count) != 0);
			compound_unlock_irqrestore(page_head, flags);

			if (put_page_testzero(page_head)) {
				if (PageHead(page_head))
					__put_compound_page(page_head);
				else
					__put_single_page(page_head);
			}
		} else {
			/* page_head is a dangling pointer */
			VM_BUG_ON(PageTail(page));
			goto out_put_single;
		}
	} else if (put_page_testzero(page)) {
		if (PageHead(page))
			__put_compound_page(page);
		else
			__put_single_page(page);
	}
}

void put_page(struct page *page)
{
	if (unlikely(PageCompound(page)))
		put_compound_page(page);
	else if (put_page_testzero(page))
		__put_single_page(page);
}
EXPORT_SYMBOL(put_page);

/*
 * This function is exported but must not be called by anything other
 * than get_page(). It implements the slow path of get_page().
 */
bool __get_page_tail(struct page *page)
{
	/*
	 * This takes care of get_page() if run on a tail page
	 * returned by one of the get_user_pages/follow_page variants.
	 * get_user_pages/follow_page itself doesn't need the compound
	 * lock because it runs __get_page_tail_foll() under the
	 * proper PT lock that already serializes against
	 * split_huge_page().
	 */
	unsigned long flags;
	bool got = false;
	struct page *page_head = compound_head(page);

	if (likely(page != page_head && get_page_unless_zero(page_head))) {
		/* Ref to put_compound_page() comment. */
		if (PageSlab(page_head) || PageHeadHuge(page_head)) {
			if (likely(PageTail(page))) {
				/*
				 * This is a hugetlbfs page or a slab
				 * page. __split_huge_page_refcount
				 * cannot race here.
				 */
				VM_BUG_ON(!PageHead(page_head));
				__get_page_tail_foll(page, false);
				return true;
			} else {
				/*
				 * __split_huge_page_refcount run
				 * before us, "page" was a THP
				 * tail. The split page_head has been
				 * freed and reallocated as slab or
				 * hugetlbfs page of smaller order
				 * (only possible if reallocated as
				 * slab on x86).
				 */
				put_page(page_head);
				return false;
			}
		}

		/*
		 * page_head wasn't a dangling pointer but it
		 * may not be a head page anymore by the time
		 * we obtain the lock. That is ok as long as it
		 * can't be freed from under us.
		 */
		flags = compound_lock_irqsave(page_head);
		/* here __split_huge_page_refcount won't run anymore */
		if (likely(PageTail(page))) {
			__get_page_tail_foll(page, false);
			got = true;
		}
		compound_unlock_irqrestore(page_head, flags);
		if (unlikely(!got))
			put_page(page_head);
	}
	return got;
}
EXPORT_SYMBOL(__get_page_tail);

/**
 * put_pages_list() - release a list of pages
 * @pages: list of pages threaded on page->lru
 *
 * Release a list of pages which are strung together on page.lru.  Currently
 * used by read_cache_pages() and related error recovery code.
 */
void put_pages_list(struct list_head *pages)
{
	while (!list_empty(pages)) {
		struct page *victim;

		victim = list_entry(pages->prev, struct page, lru);
		list_del(&victim->lru);
		page_cache_release(victim);
	}
}
EXPORT_SYMBOL(put_pages_list);

/*
 * get_kernel_pages() - pin kernel pages in memory
 * @kiov:	An array of struct kvec structures
 * @nr_segs:	number of segments to pin
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_segs long.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with.
 */
int get_kernel_pages(const struct kvec *kiov, int nr_segs, int write,
		struct page **pages)
{
	int seg;

	for (seg = 0; seg < nr_segs; seg++) {
		if (WARN_ON(kiov[seg].iov_len != PAGE_SIZE))
			return seg;

		pages[seg] = kmap_to_page(kiov[seg].iov_base);
		page_cache_get(pages[seg]);
	}

	return seg;
}
EXPORT_SYMBOL_GPL(get_kernel_pages);

/*
 * get_kernel_page() - pin a kernel page in memory
 * @start:	starting kernel address
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointer to the page pinned.
 *		Must be at least nr_segs long.
 *
 * Returns 1 if page is pinned. If the page was not pinned, returns
 * -errno. The page returned must be released with a put_page() call
 * when it is finished with.
 */
int get_kernel_page(unsigned long start, int write, struct page **pages)
{
	const struct kvec kiov = {
		.iov_base = (void *)start,
		.iov_len = PAGE_SIZE
	};

	return get_kernel_pages(&kiov, 1, write, pages);
}
EXPORT_SYMBOL_GPL(get_kernel_page);

static void pagevec_lru_move_fn(struct pagevec *pvec,
	void (*move_fn)(struct page *page, struct lruvec *lruvec, void *arg),
	void *arg)
{
	int i;
	struct zone *zone = NULL;
	struct lruvec *lruvec;
	unsigned long flags = 0;
    //遍历lru缓存上的PAGEVEC_SIZE个page
	for (i = 0; i < pagevec_count(pvec); i++) {
        //依次取出lru缓存保存的page
		struct page *page = pvec->pages[i];
		struct zone *pagezone = page_zone(page);

        //上一个page和这个page不属于同一个zone，则要把上个zone的lock锁解除再把当前page所在zone加锁
		if (pagezone != zone) {
			if (zone)
				spin_unlock_irqrestore(&zone->lru_lock, flags);
			zone = pagezone;
			spin_lock_irqsave(&zone->lru_lock, flags);
		}
        //根据page返回lruvec
		lruvec = mem_cgroup_page_lruvec(page, zone);
        //设置page属性，把page添加到对应属性的lru链表(active/inactive file/anon)，mem cgroup中增加page个数统计，增加lru链表中page计数
		(*move_fn)(page, lruvec, arg);//__pagevec_lru_add_fn/__activate_page/pagevec_move_tail_fn
	}
	if (zone)
		spin_unlock_irqrestore(&zone->lru_lock, flags);
	release_pages(pvec->pages, pvec->nr, pvec->cold);
	pagevec_reinit(pvec);
}
//把page添加到file/anon inactive lru链表尾部，此时page对应的数据已经刷回磁盘，把page放到inactive lru链表尾部，下次内存回收局释放掉该page
static void pagevec_move_tail_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	int *pgmoved = arg;
    //page有lru属性，page没有active属性，page没有不可回收属性
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		enum lru_list lru = page_lru_base_type(page);//返回LRU_INACTIVE_ANON或LRU_INACTIVE_FILE，都是inactive 
		list_move_tail(&page->lru, &lruvec->lists[lru]);
		(*pgmoved)++;
	}
}

/*
 * pagevec_move_tail() must be called with IRQ disabled.
 * Otherwise this may cause nasty races.
 */
static void pagevec_move_tail(struct pagevec *pvec)
{
	int pgmoved = 0;
    //把page添加到file/anon inactive lru链表尾部.page对应的数据已经刷回磁盘，把page放到inactive lru链表尾部，下次内存回收局释放掉该page
	pagevec_lru_move_fn(pvec, pagevec_move_tail_fn, &pgmoved);
	__count_vm_events(PGROTATED, pgmoved);
}

/*
 * Writeback is about to end against a page which has been marked for immediate
 * reclaim.  If it still appears to be reclaimable, move it to the tail of the
 * inactive list.
 */
//内存回收完成后，被标记"reclaimable"的page的数据刷入了磁盘，执行rotate_reclaimable_page->end_page_writeback把该page移动到
//inactive lru链表链表，下轮内存回收就会释放该page到伙伴系统
void rotate_reclaimable_page(struct page *page)
{
    //page没有上PG_locked，page不是脏页，page被标记acive标记，page没有设置不可回收标记，page在lru链表
	if (!PageLocked(page) && !PageDirty(page) && !PageActive(page) &&
	    !PageUnevictable(page) && PageLRU(page)) {
		struct pagevec *pvec;
		unsigned long flags;
        //page->count ++
		page_cache_get(page);
		local_irq_save(flags);
        //取出本地cpu lru缓存pagevec
		pvec = &__get_cpu_var(lru_rotate_pvecs);
        
        //先尝试把page添加到本地cpu lru缓存pagevec，如果添加后lru缓存pagevec满了，则把lru缓存pagevec中的所有page移动到inactive lru链表
		if (!pagevec_add(pvec, page))
			pagevec_move_tail(pvec);
		local_irq_restore(flags);
	}
}

static void update_page_reclaim_stat(struct lruvec *lruvec,
				     int file, int rotated)
{
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;

	reclaim_stat->recent_scanned[file]++;
	if (rotated)
		reclaim_stat->recent_rotated[file]++;
}
//把page从inactive lru链表剔除，添加到active lru链表
static void __activate_page(struct page *page, struct lruvec *lruvec,
			    void *arg)
{
    //if成立条件:page在lru链表，page没有Active属性，page可回收
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
        //page是文件缓存才返回1
		int file = page_is_file_cache(page);
        //返回base lru:文件缓存返回LRU_INACTIVE_FILE ，否则LRU_INACTIVE_ANON
		int lru = page_lru_base_type(page);
        //page从原inactive lru链表剔除，page肯定在inactive lru链表，因为page此时没有Active属性
		del_page_from_lru_list(page, lruvec, lru);

        //设置page的Active属性
		SetPageActive(page);
        //lru += LRU_ACTIVE后，lru指向active lru链表
		lru += LRU_ACTIVE;
        //page添加到active lru链表
		add_page_to_lru_list(page, lruvec, lru);

		__count_vm_event(PGACTIVATE);
		update_page_reclaim_stat(lruvec, file, 1);
	}
}

#ifdef CONFIG_SMP//yes
static DEFINE_PER_CPU(struct pagevec, activate_page_pvecs);

static void activate_page_drain(int cpu)
{
	struct pagevec *pvec = &per_cpu(activate_page_pvecs, cpu);

	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, __activate_page, NULL);
}

void activate_page(struct page *page)
{
    //if成立条件:page在链入链表，page没有Active标记,page可回收
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
        //取出activate_page_pvecs 本次cpu lru缓存pagevec
		struct pagevec *pvec = &get_cpu_var(activate_page_pvecs);
        //page->count加1
		page_cache_get(page);
        //先尝试把page添加到本地cpu lru缓存pagevec，如果添加后lru缓存pagevec满了，则把lru缓存中的所有page移动到active lru链表
		if (!pagevec_add(pvec, page))
			pagevec_lru_move_fn(pvec, __activate_page, NULL);//把lru缓存中的所有page移动到active lru链表
        
		put_cpu_var(activate_page_pvecs);
	}
}

#else
static inline void activate_page_drain(int cpu)
{
}

void activate_page(struct page *page)
{
	struct zone *zone = page_zone(page);

	spin_lock_irq(&zone->lru_lock);
	__activate_page(page, mem_cgroup_page_lruvec(page, zone), NULL);
	spin_unlock_irq(&zone->lru_lock);
}
#endif

/*
 * Mark a page as having seen activity.
 *
 * inactive,unreferenced	->	inactive,referenced
 * inactive,referenced		->	active,unreferenced
 * active,unreferenced		->	active,referenced
 */
void mark_page_accessed(struct page *page)
{
	if (!PageActive(page) && !PageUnevictable(page) &&
			PageReferenced(page) && PageLRU(page)) {
		activate_page(page);
		ClearPageReferenced(page);
	} else if (!PageReferenced(page)) {
		SetPageReferenced(page);
	}
}
EXPORT_SYMBOL(mark_page_accessed);

/*
 * Order of operations is important: flush the pagevec when it's already
 * full, not when adding the last page, to make sure that last page is
 * not added to the LRU directly when passed to this function. Because
 * mark_page_accessed() (called after this when writing) only activates
 * pages that are on the LRU, linear writes in subpage chunks would see
 * every PAGEVEC_SIZE page activated, which is unexpected.
 */
//尝试把page添加到lru_add_pvecs[lru]这个lru缓存，lru缓存满了则把lru缓存的page添加到lru链表
void __lru_cache_add(struct page *page, enum lru_list lru)
{
    //得到当前cpu的lru_add_pvecs链表上lru编号指定属性的lru缓存pagevec
	struct pagevec *pvec = &get_cpu_var(lru_add_pvecs)[lru];

	page_cache_get(page);
    //如果当前cpu lru缓存已经存放了14个page，满了，先把这14个page移动到lru链表，下边再把这个新的page添加到lru缓存
	if (!pagevec_space(pvec))
		__pagevec_lru_add(pvec, lru);
    
    //把page添加到lru缓存链表，其实只是把page指针保存到pvec->pages[]数组而已，即pvec->pages[pvec->nr++] = page
	pagevec_add(pvec, page);
	put_cpu_var(lru_add_pvecs);
}
EXPORT_SYMBOL(__lru_cache_add);

/**
 * lru_cache_add_lru - add a page to a page list
 * @page: the page to be added to the LRU.
 * @lru: the LRU list to which the page is added.
 */
void lru_cache_add_lru(struct page *page, enum lru_list lru)
{
	if (PageActive(page)) {
		VM_BUG_ON(PageUnevictable(page));
		ClearPageActive(page);
	} else if (PageUnevictable(page)) {
		VM_BUG_ON(PageActive(page));
		ClearPageUnevictable(page);
	}

	VM_BUG_ON(PageLRU(page) || PageActive(page) || PageUnevictable(page));
    //尝试把page添加到lru缓存，lru缓存满了则把lru缓存的所有page添加到lru链表
	__lru_cache_add(page, lru);
}

/**
 * add_page_to_unevictable_list - add a page to the unevictable list
 * @page:  the page to be added to the unevictable list
 *
 * Add page directly to its zone's unevictable list.  To avoid races with
 * tasks that might be making the page evictable, through eg. munlock,
 * munmap or exit, while it's not on the lru, we want to add the page
 * while it's locked or otherwise "invisible" to other tasks.  This is
 * difficult to do when using the pagevec cache, so bypass that.
 */
void add_page_to_unevictable_list(struct page *page)
{
	struct zone *zone = page_zone(page);
	struct lruvec *lruvec;

	spin_lock_irq(&zone->lru_lock);
    //取出lruvec
	lruvec = mem_cgroup_page_lruvec(page, zone);
	SetPageUnevictable(page);
	SetPageLRU(page);
	add_page_to_lru_list(page, lruvec, LRU_UNEVICTABLE);
	spin_unlock_irq(&zone->lru_lock);
}

/*
 * If the page can not be invalidated, it is moved to the
 * inactive list to speed up its reclaim.  It is moved to the
 * head of the list, rather than the tail, to give the flusher
 * threads some time to write it out, as this is much more
 * effective than the single-page writeout from reclaim.
 *
 * If the page isn't page_mapped and dirty/writeback, the page
 * could reclaim asap using PG_reclaim.
 *
 * 1. active, mapped page -> none
 * 2. active, dirty/writeback page -> inactive, head, PG_reclaim
 * 3. inactive, mapped page -> none
 * 4. inactive, dirty/writeback page -> inactive, head, PG_reclaim
 * 5. inactive, clean -> inactive, tail
 * 6. Others -> none
 *
 * In 4, why it moves inactive's head, the VM expects the page would
 * be write it out by flusher threads as this is much more effective
 * than the single-page writeout from reclaim.
 */
//把page从active lru链表剔除，添加到inactive lru链表头部
static void lru_deactivate_fn(struct page *page, struct lruvec *lruvec,
			      void *arg)
{
	int lru, file;
	bool active;

	if (!PageLRU(page))//page不在lru链表
		return;

	if (PageUnevictable(page))//page不可回收
		return;

	/* Some processes are using the page */
	if (page_mapped(page))//page没有文件映射
		return;
    //page是否active，应该是active
	active = PageActive(page);
    //如果page是文件缓存返回1
	file = page_is_file_cache(page);
    //如果page是文件缓存返回LRU_INACTIVE_FILE，否则返回LRU_INACTIVE_ANON
	lru = page_lru_base_type(page);

    //把page从active链表剔除，lru代表inactive链表，lru + active代表active lru链表
	del_page_from_lru_list(page, lruvec, lru + active);
	ClearPageActive(page);
	ClearPageReferenced(page);
    //把page添加到inactive lru链表，应该是链表头部，不是链表尾部
	add_page_to_lru_list(page, lruvec, lru);
    //如果page是正在回写或者脏页状态
	if (PageWriteback(page) || PageDirty(page)) {
		/*
		 * PG_reclaim could be raced with end_page_writeback
		 * It can make readahead confusing.  But race window
		 * is _really_ small and  it's non-critical problem.
		 */
		//设置page Reclaim状态
		SetPageReclaim(page);
	} else {
		/*
		 * The page's writeback ends up during pagevec
		 * We moves tha page into tail of inactive.
		 */
		//把page添加到inactive lru链表尾部，这个page是干净的，下次内存回收就释放它
		list_move_tail(&page->lru, &lruvec->lists[lru]);
		__count_vm_event(PGROTATED);
	}

	if (active)
		__count_vm_event(PGDEACTIVATE);
	update_page_reclaim_stat(lruvec, file, 0);
}

/*
 * Drain pages out of the cpu's pagevecs.
 * Either "cpu" is the current CPU, and preemption has already been
 * disabled; or "cpu" is being hot-unplugged, and is already dead.
 */
//把cpu本地所有lru缓存上的page移动到 active/inactive lru链表
void lru_add_drain_cpu(int cpu)
{
    //取出lru_add_pvecs这个pagevec
	struct pagevec *pvecs = per_cpu(lru_add_pvecs, cpu);
	struct pagevec *pvec;
	int lru;

    //取出lru_add_pvecs相关的所有pagevec，把里边的page添加到active 
	for_each_lru(lru) {
		pvec = &pvecs[lru - LRU_BASE];
		if (pagevec_count(pvec))//该pagevec有page
			__pagevec_lru_add(pvec, lru);//把page添加到对应属性的lru链表
	}
    
    //取出lru_rotate_pvecs这个pagevec
	pvec = &per_cpu(lru_rotate_pvecs, cpu);
	if (pagevec_count(pvec)) {//该pagevec有page
		unsigned long flags;

		/* No harm done if a racing interrupt already did this */
		local_irq_save(flags);
		pagevec_move_tail(pvec);//把page添加到inactive lru链表尾部
		local_irq_restore(flags);
	}
    
    //取出lru_deactivate_pvecs这个pagevec
	pvec = &per_cpu(lru_deactivate_pvecs, cpu);
	if (pagevec_count(pvec))//该pagevec有page
		pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);//把page添加到inactive lru链表头部

	activate_page_drain(cpu);
}

/**
 * deactivate_page - forcefully deactivate a page
 * @page: page to deactivate
 *
 * This function hints the VM that @page is a good reclaim candidate,
 * for example if its invalidation fails due to the page being dirty
 * or under writeback.
 */
void deactivate_page(struct page *page)
{
	/*
	 * In a workload with many unevictable page such as mprotect, unevictable
	 * page deactivation for accelerating reclaim is pointless.
	 */
	if (PageUnevictable(page))//page不可回收
		return;

	if (likely(get_page_unless_zero(page))) {
        //取出cpu本地lru_deactivate_pvecs lru缓存pagevec
		struct pagevec *pvec = &get_cpu_var(lru_deactivate_pvecs);
        
        //先尝试把page添加到本地cpu lru缓存pagevec，如果添加后lru缓存pagevec满了，则把lru缓存pagevec中的所有page移动到inactive lru链表
		if (!pagevec_add(pvec, page))
			pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);
        
		put_cpu_var(lru_deactivate_pvecs);
	}
}
//把cpu本地所有lru缓存上的page移动到 active/inactive lru链表
void lru_add_drain(void)
{
	lru_add_drain_cpu(get_cpu());
	put_cpu();
}

static void lru_add_drain_per_cpu(struct work_struct *dummy)
{
	lru_add_drain();
}

/*
 * Returns 0 for success
 */
int lru_add_drain_all(void)
{
	return schedule_on_each_cpu(lru_add_drain_per_cpu);
}

/*
 * Batched page_cache_release().  Decrement the reference count on all the
 * passed pages.  If it fell to zero then remove the page from the LRU and
 * free it.
 *
 * Avoid taking zone->lru_lock if possible, but if it is taken, retain it
 * for the remainder of the operation.
 *
 * The locking in this function is against shrink_inactive_list(): we recheck
 * the page count inside the lock to see whether shrink_inactive_list()
 * grabbed the page via the LRU.  If it did, give up: shrink_inactive_list()
 * will free it.
 */
void release_pages(struct page **pages, int nr, int cold)
{
	int i;
	LIST_HEAD(pages_to_free);
	struct zone *zone = NULL;
	struct lruvec *lruvec;
	unsigned long uninitialized_var(flags);

	for (i = 0; i < nr; i++) {
		struct page *page = pages[i];

		if (unlikely(PageCompound(page))) {
			if (zone) {
				spin_unlock_irqrestore(&zone->lru_lock, flags);
				zone = NULL;
			}
			put_compound_page(page);
			continue;
		}

		if (!put_page_testzero(page))
			continue;

		if (PageLRU(page)) {
			struct zone *pagezone = page_zone(page);

			if (pagezone != zone) {
				if (zone)
					spin_unlock_irqrestore(&zone->lru_lock,
									flags);
				zone = pagezone;
				spin_lock_irqsave(&zone->lru_lock, flags);
			}

			lruvec = mem_cgroup_page_lruvec(page, zone);
			VM_BUG_ON(!PageLRU(page));
			__ClearPageLRU(page);
			del_page_from_lru_list(page, lruvec, page_off_lru(page));
		}

		list_add(&page->lru, &pages_to_free);
	}
	if (zone)
		spin_unlock_irqrestore(&zone->lru_lock, flags);

	free_hot_cold_page_list(&pages_to_free, cold);//这里会更新NR_FREE_PAGES减少 1 << order
}
EXPORT_SYMBOL(release_pages);

/*
 * The pages which we're about to release may be in the deferred lru-addition
 * queues.  That would prevent them from really being freed right now.  That's
 * OK from a correctness point of view but is inefficient - those pages may be
 * cache-warm and we want to give them back to the page allocator ASAP.
 *
 * So __pagevec_release() will drain those queues here.  __pagevec_lru_add()
 * and __pagevec_lru_add_active() call release_pages() directly to avoid
 * mutual recursion.
 */
void __pagevec_release(struct pagevec *pvec)
{
	lru_add_drain();
	release_pages(pvec->pages, pagevec_count(pvec), pvec->cold);
	pagevec_reinit(pvec);
}
EXPORT_SYMBOL(__pagevec_release);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/* used by __split_huge_page_refcount() */
void lru_add_page_tail(struct page *page, struct page *page_tail,
		       struct lruvec *lruvec, struct list_head *list)
{
	int uninitialized_var(active);
	enum lru_list lru;
	const int file = 0;

	VM_BUG_ON(!PageHead(page));
	VM_BUG_ON(PageCompound(page_tail));
	VM_BUG_ON(PageLRU(page_tail));
	VM_BUG_ON(NR_CPUS != 1 &&
		  !spin_is_locked(&lruvec_zone(lruvec)->lru_lock));

	if (!list)
		SetPageLRU(page_tail);

	if (page_evictable(page_tail)) {
		if (PageActive(page)) {
			SetPageActive(page_tail);
			active = 1;
			lru = LRU_ACTIVE_ANON;
		} else {
			active = 0;
			lru = LRU_INACTIVE_ANON;
		}
	} else {
		SetPageUnevictable(page_tail);
		lru = LRU_UNEVICTABLE;
	}

	if (likely(PageLRU(page)))
		list_add_tail(&page_tail->lru, &page->lru);
	else if (list) {
		/* page reclaim is reclaiming a huge page */
		get_page(page_tail);
		list_add_tail(&page_tail->lru, list);
	} else {
		struct list_head *list_head;
		/*
		 * Head page has not yet been counted, as an hpage,
		 * so we must account for each subpage individually.
		 *
		 * Use the standard add function to put page_tail on the list,
		 * but then correct its position so they all end up in order.
		 */
		add_page_to_lru_list(page_tail, lruvec, lru);
		list_head = page_tail->lru.prev;
		list_move_tail(&page_tail->lru, list_head);
	}

	if (!PageUnevictable(page))
		update_page_reclaim_stat(lruvec, file, active);
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
//设置page的lru和active属性，把page添加到lru编号指定属性的lru链表，mem cgroup中增加page个数统计，增加lru编号指定属性的page计数
static void __pagevec_lru_add_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)//arg就是lru的active、inactive、file、anon属性编号
{
	enum lru_list lru = (enum lru_list)arg;
	int file = is_file_lru(lru);//文件页?匿名页?
	int active = is_active_lru(lru);//active?inactive?

	VM_BUG_ON(PageActive(page));
	VM_BUG_ON(PageUnevictable(page));
	VM_BUG_ON(PageLRU(page));
    //设置page的lru属性
	SetPageLRU(page);
	if (active)//设置page的active属性
		SetPageActive(page);
    //把page添加到lru编号指定属性的lru链表，mem cgroup中增加page个数统计，增加lru编号指定属性的page计数
	add_page_to_lru_list(page, lruvec, lru);
	update_page_reclaim_stat(lruvec, file, active);
}

/*
 * Add the passed pages to the LRU, then drop the caller's refcount
 * on them.  Reinitialises the caller's pagevec.
 */
void __pagevec_lru_add(struct pagevec *pvec, enum lru_list lru)
{
	VM_BUG_ON(is_unevictable_lru(lru));
    //把pvec这个lru缓存中14个page添加到对应lru链表，增加page统计计数，
	pagevec_lru_move_fn(pvec, __pagevec_lru_add_fn, (void *)lru);
}
EXPORT_SYMBOL(__pagevec_lru_add);

/**
 * pagevec_lookup - gang pagecache lookup
 * @pvec:	Where the resulting pages are placed
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 *
 * pagevec_lookup() will search for and return a group of up to @nr_pages pages
 * in the mapping.  The pages are placed in @pvec.  pagevec_lookup() takes a
 * reference against the pages in @pvec.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * pagevec_lookup() returns the number of pages which were found.
 */
unsigned pagevec_lookup(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t start, unsigned nr_pages)
{
	pvec->nr = find_get_pages(mapping, start, nr_pages, pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup);

unsigned pagevec_lookup_tag(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t *index, int tag, unsigned nr_pages)
{
	pvec->nr = find_get_pages_tag(mapping, index, tag,
					nr_pages, pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup_tag);

/*
 * Perform any setup for the swap system
 */
void __init swap_setup(void)
{
	unsigned long megs = totalram_pages >> (20 - PAGE_SHIFT);
#ifdef CONFIG_SWAP
	int i;

	bdi_init(swapper_spaces[0].backing_dev_info);
	for (i = 0; i < MAX_SWAPFILES; i++) {
		spin_lock_init(&swapper_spaces[i].tree_lock);
		INIT_LIST_HEAD(&swapper_spaces[i].i_mmap_nonlinear);
	}
#endif

	/* Use a smaller cluster for small-memory machines */
	if (megs < 16)
		page_cluster = 2;
	else
		page_cluster = 3;
	/*
	 * Right now other parts of the system means that we
	 * _really_ don't want to cluster much more
	 */
}
