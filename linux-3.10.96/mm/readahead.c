/*
 * mm/readahead.c - address_space-level file readahead.
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 09Apr2002	Andrew Morton
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/pagevec.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/file.h>

/*
 * Initialise a struct file's readahead state.  Assumes that the caller has
 * memset *ra to zero.
 */
void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping)
{
	ra->ra_pages = mapping->backing_dev_info->ra_pages;
	ra->prev_pos = -1;
}
EXPORT_SYMBOL_GPL(file_ra_state_init);

#define list_to_page(head) (list_entry((head)->prev, struct page, lru))

/*
 * see if a page needs releasing upon read_cache_pages() failure
 * - the caller of read_cache_pages() may have set PG_private or PG_fscache
 *   before calling, such as the NFS fs marking pages that are cached locally
 *   on disk, thus we need to give the fs a chance to clean up in the event of
 *   an error
 */
static void read_cache_pages_invalidate_page(struct address_space *mapping,
					     struct page *page)
{
	if (page_has_private(page)) {
		if (!trylock_page(page))
			BUG();
		page->mapping = mapping;
		do_invalidatepage(page, 0);
		page->mapping = NULL;
		unlock_page(page);
	}
	page_cache_release(page);
}

/*
 * release a list of pages, invalidating them first if need be
 */
static void read_cache_pages_invalidate_pages(struct address_space *mapping,
					      struct list_head *pages)
{
	struct page *victim;

	while (!list_empty(pages)) {
		victim = list_to_page(pages);
		list_del(&victim->lru);
		read_cache_pages_invalidate_page(mapping, victim);
	}
}

/**
 * read_cache_pages - populate an address space with some pages & start reads against them
 * @mapping: the address_space
 * @pages: The address of a list_head which contains the target pages.  These
 *   pages have their ->index populated and are otherwise uninitialised.
 * @filler: callback routine for filling a single page.
 * @data: private data for the callback routine.
 *
 * Hides the details of the LRU cache etc from the filesystems.
 */
//fuse_readpages->read_cache_pages
int read_cache_pages(struct address_space *mapping, struct list_head *pages,
			int (*filler)(void *, struct page *), void *data)
{
	struct page *page;
	int ret = 0;

	while (!list_empty(pages)) {
        //取出page
		page = list_to_page(pages);
		list_del(&page->lru);
		if (add_to_page_cache_lru(page, mapping,
					page->index, GFP_KERNEL)) {
			read_cache_pages_invalidate_page(mapping, page);
			continue;
		}
		page_cache_release(page);

		ret = filler(data, page);//即 fuse_readpages_fill
		if (unlikely(ret)) {
			read_cache_pages_invalidate_pages(mapping, pages);
			break;
		}
		task_io_account_read(PAGE_CACHE_SIZE);
	}
	return ret;
}

EXPORT_SYMBOL(read_cache_pages);

static int read_pages(struct address_space *mapping, struct file *filp,
		struct list_head *pages, unsigned nr_pages)//遇到的page在struct list_head *pages这个链表，nr_pages是预读page数
{
	struct blk_plug plug;
	unsigned page_idx;
	int ret;

	blk_start_plug(&plug);

	if (mapping->a_ops->readpages) {
        //具体文件系统read函数ext4_readpages，实际测试执行的是这个函数，一次读取nr_pages个page
		ret = mapping->a_ops->readpages(filp, mapping, pages, nr_pages);
		/* Clean up the remaining pages */
		put_pages_list(pages);
		goto out;
	}

	for (page_idx = 0; page_idx < nr_pages; page_idx++) {
        //每次都从struct list_head *pages链表头取出page，依次取完这个链表上的所有page
		struct page *page = list_to_page(pages);
		list_del(&page->lru);//把page从struct list_head *pages这个临时链表剔除
		//再把page添加到文件页高速缓存mapping的radix tree和lru链表
		if (!add_to_page_cache_lru(page, mapping,
					page->index, GFP_KERNEL)) {
		    //具体文件系统read函数,ext4的是ext4_readpage，执行完这个函数，文件数据并没有读取到page文件页
			mapping->a_ops->readpage(filp, page);
		}
		page_cache_release(page);
	}
	ret = 0;

out:
    //真正启动文件系统block层磁盘数据传输，异步的，执行完该函数并不能保证文件数据已经传输到page文件页指向的内存
	blk_finish_plug(&plug);

	return ret;
}

/*
 * __do_page_cache_readahead() actually reads a chunk of disk.  It allocates all
 * the pages first, then submits them all for I/O. This avoids the very bad
 * behaviour which would occur if page allocations are causing VM writeback.
 * We really don't want to intermingle reads and writes like that.
 *
 * Returns the number of pages requested, or the maximum amount of I/O allowed.
 */
static int
__do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			pgoff_t offset, unsigned long nr_to_read,
			unsigned long lookahead_size)
{
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long end_index;	/* The last page we want to read */
	LIST_HEAD(page_pool);
	int page_idx;
	int ret = 0;
	loff_t isize = i_size_read(inode);

	if (isize == 0)
		goto out;

	end_index = ((isize - 1) >> PAGE_CACHE_SHIFT);

	/*
	 * Preallocate as many pages as we will need.
	 */
	//nr_to_read是上层传入的预读的总文件页数,offset是预读的起始文件页
	for (page_idx = 0; page_idx < nr_to_read; page_idx++) {
        //page_offset预读的文件页索引
		pgoff_t page_offset = offset + page_idx;

		if (page_offset > end_index)
			break;

		rcu_read_lock();
        //按照page_offset这个page索引，在文件页高速缓存radix tree中查找是否是否已经有了该page
		page = radix_tree_lookup(&mapping->page_tree, page_offset);
		rcu_read_unlock();
		if (page)
			continue;
        //radix tree找不到页索引是page_offset的page，则分配一个新的page
		page = page_cache_alloc_readahead(mapping);
		if (!page)
			break;
		page->index = page_offset;//新分配的page的页索引
		list_add(&page->lru, &page_pool);//把预读的page添加到page_pool链表
		
         //是本次真正预读的第一个page，预读窗口page数ra->size减去真正预读的page数ra->async_size的结果
		if (page_idx == nr_to_read - lookahead_size)
			SetPageReadahead(page);//设置该page的"PageReadahead"预读标记
		ret++;
	}

	/*
	 * Now start the IO.  We ignore I/O errors - if the page is not
	 * uptodate then the caller will launch readpage again, and
	 * will then handle the error.
	 */
	//ret表示预读的page数
	if (ret)
		read_pages(mapping, filp, &page_pool, ret);//这里调用文件系统read接口发起读取文件数据到page文件页指向的内存
	BUG_ON(!list_empty(&page_pool));
out:
	return ret;
}

/*
 * Chunk the readahead into 2 megabyte units, so that we don't pin too much
 * memory at once.
 */
int force_page_cache_readahead(struct address_space *mapping, struct file *filp,
		pgoff_t offset, unsigned long nr_to_read)
{
	int ret = 0;

	if (unlikely(!mapping->a_ops->readpage && !mapping->a_ops->readpages))
		return -EINVAL;

	nr_to_read = max_sane_readahead(nr_to_read);
	while (nr_to_read) {
		int err;

		unsigned long this_chunk = (2 * 1024 * 1024) / PAGE_CACHE_SIZE;

		if (this_chunk > nr_to_read)
			this_chunk = nr_to_read;
		err = __do_page_cache_readahead(mapping, filp,
						offset, this_chunk, 0);
		if (err < 0) {
			ret = err;
			break;
		}
		ret += err;
		offset += this_chunk;
		nr_to_read -= this_chunk;
	}
	return ret;
}

/*
 * Given a desired number of PAGE_CACHE_SIZE readahead pages, return a
 * sensible upper limit.
 */
unsigned long max_sane_readahead(unsigned long nr)
{
	return min(nr, (node_page_state(numa_node_id(), NR_INACTIVE_FILE)
		+ node_page_state(numa_node_id(), NR_FREE_PAGES)) / 2);
}

/*
 * Submit IO for the read-ahead request in file_ra_state.
 */
unsigned long ra_submit(struct file_ra_state *ra,
		       struct address_space *mapping, struct file *filp)
{
	int actual;

	actual = __do_page_cache_readahead(mapping, filp,
					ra->start, ra->size, ra->async_size);

	return actual;
}

/*
 * Set the initial window size, round to next power of 2 and square
 * for small size, x 4 for medium, and x 2 for large
 * for 128k (32 page) max ra
 * 1-8 page = 32k initial, > 8 page = 128k initial
 */
//其实就是根据最大预读page数max调整预读page数newsize
static unsigned long get_init_ra_size(unsigned long size, unsigned long max)//size:16  newsize:64
{
	unsigned long newsize = roundup_pow_of_two(size);

	if (newsize <= max / 32)
		newsize = newsize * 4;
	else if (newsize <= max / 4)
		newsize = newsize * 2;
	else
		newsize = max;

	return newsize;
}

/*
 *  Get the previous window size, ramp it up, and
 *  return it as the new window size.
 */
static unsigned long get_next_ra_size(struct file_ra_state *ra,
						unsigned long max)
{
	unsigned long cur = ra->size;
	unsigned long newsize;

	if (cur < max / 16)
		newsize = 4 * cur;//ra->size的4倍
	else
		newsize = 2 * cur;

	return min(newsize, max);
}

/*
 * On-demand readahead design.
 *
 * The fields in struct file_ra_state represent the most-recently-executed
 * readahead attempt:
 *
 *                        |<----- async_size ---------|
 *     |------------------- size -------------------->|
 *     |==================#===========================|
 *     ^start             ^page marked with PG_readahead
 *
 * To overlap application thinking time and disk I/O time, we do
 * `readahead pipelining': Do not wait until the application consumed all
 * readahead pages and stalled on the missing page at readahead_index;
 * Instead, submit an asynchronous readahead I/O as soon as there are
 * only async_size pages left in the readahead window. Normally async_size
 * will be equal to size, for maximum pipelining.
 *
 * In interleaved sequential reads, concurrent streams on the same fd can
 * be invalidating each other's readahead state. So we flag the new readahead
 * page at (start+size-async_size) with PG_readahead, and use it as readahead
 * indicator. The flag won't be set on already cached pages, to avoid the
 * readahead-for-nothing fuss, saving pointless page cache lookups.
 *
 * prev_pos tracks the last visited byte in the _previous_ read request.
 * It should be maintained by the caller, and will be used for detecting
 * small random reads. Note that the readahead algorithm checks loosely
 * for sequential patterns. Hence interleaved reads might be served as
 * sequential ones.
 *
 * There is a special-case: if the first page which the application tries to
 * read happens to be the first page of the file, it is assumed that a linear
 * read is about to happen and the window is immediately set to the initial size
 * based on I/O request size and the max_readahead.
 *
 * The code ramps up the readahead size aggressively at first, but slow down as
 * it approaches max_readhead.
 */

/*
 * Count contiguously cached pages from @offset-1 to @offset-@max,
 * this count is a conservative estimation of
 * 	- length of the sequential read sequence, or
 * 	- thrashing threshold in memory tight systems
 */
static pgoff_t count_history_pages(struct address_space *mapping,
				   struct file_ra_state *ra,
				   pgoff_t offset, unsigned long max)
{
	pgoff_t head;

	rcu_read_lock();
	head = radix_tree_prev_hole(&mapping->page_tree, offset - 1, max);
	rcu_read_unlock();

	return offset - 1 - head;
}

/*
 * page cache context based read-ahead
 */
static int try_context_readahead(struct address_space *mapping,
				 struct file_ra_state *ra,
				 pgoff_t offset,
				 unsigned long req_size,
				 unsigned long max)
{
	pgoff_t size;

	size = count_history_pages(mapping, ra, offset, max);

	/*
	 * no history pages:
	 * it could be a random read
	 */
	if (!size)
		return 0;

	/*
	 * starts from beginning of file:
	 * it is a strong indication of long-run stream (or whole-file-read)
	 */
	if (size >= offset)
		size *= 2;

	ra->start = offset;
	ra->size = get_init_ra_size(size + req_size, max);
	ra->async_size = ra->size;

	return 1;
}

/*
 * A minimal readahead algorithm for trivial sequential/random reads.
 */

/*
hit_readahead_marker:同步预读false,异步预读true
offset:do_generic_file_read函数里，本轮for循环要读取文件页page索引
req_size:do_generic_file_read函数里，last_index - index，就是本次read系统调用还剩余多少个没读取文件页page数
*/
static unsigned long
ondemand_readahead(struct address_space *mapping,
		   struct file_ra_state *ra, struct file *filp,
		   bool hit_readahead_marker, pgoff_t offset,//
		   unsigned long req_size)
{
    //不同系统不一样，虚拟机里测试时max=2048
	unsigned long max = max_sane_readahead(ra->ra_pages);

	/*
	 * start of file
	 */
	if (!offset)//第一次读文件，从文件头开始预读
		goto initial_readahead;

	/*
	 * It's the expected callback offset, assume sequential access.
	 * Ramp up sizes, and push forward the readahead window.
	 */
	if ((offset == (ra->start + ra->size - ra->async_size) ||
	     offset == (ra->start + ra->size))) {//本次读取的page页索引等于预读窗口的结束page索引?可能成立吗，搞不清楚这个for循环的意义
		ra->start += ra->size;
		ra->size = get_next_ra_size(ra, max);
		ra->async_size = ra->size;
		goto readit;
	}

	/*
	 * Hit a marked page without valid readahead state.
	 * E.g. interleaved reads.
	 * Query the pagecache for async_size, which normally equals to
	 * readahead size. Ramp it up and use it as the new readahead size.
	 */
	if (hit_readahead_marker) {//传输中的异步预读，搞不清楚到底与同步预读有啥区别
		pgoff_t start;

		rcu_read_lock();
        //从本次要实际读取的文件页page索引offset后开始搜索:在radix tree找到第一个hole index，hole index索引对应的page还没创建，
        //对应索引的文件4K数据还没读取到这个page(简单说这是第一个还没跟文件建立映射的文件页，这个page是个空洞hole)。
        //这个hole index就是本次预读窗口的第一个page索引
		start = radix_tree_next_hole(&mapping->page_tree, offset+1,max);
		rcu_read_unlock();

		if (!start || start - offset > max)
			return 0;
        
		ra->start = start;//该文件第一个hole index，是预读窗口的第一个page
		//预读窗口大小(预读page文件页数)，这是啥算法，就用个预读窗口起始page索引-本次要读取的文件页索引糊弄?
		ra->size = start - offset;	/* old async_size */
		ra->size += req_size;//预读窗口大小再加上本次read系统调用还剩余多少个没读取文件页page数
		//根据预读窗口大小和max重新计算预读窗口大小，折腾
		ra->size = get_next_ra_size(ra, max);
        //ra->async_size初值与ra->size一直
		ra->async_size = ra->size;
		goto readit;
	}

	/*
	 * oversize read
	 */
	//如果还没读取文件页个数大于单次最大预读page数
	if (req_size > max)
		goto initial_readahead;

	/*
	 * sequential cache miss
	 */
	//(ra->prev_pos >> PAGE_CACHE_SHIFT)是上次read读取文件的最后一个page文件页索引，不包含预读的
	//这个if一般情况不成立吧，除非重定向了文件指针?然后就goto initial_readahead重新初始化预读窗口
	if (offset - (ra->prev_pos >> PAGE_CACHE_SHIFT) <= 1UL)
		goto initial_readahead;

	/*
	 * Query the page cache and look for the traces(cached history pages)
	 * that a sequential stream would leave behind.
	 */
	if (try_context_readahead(mapping, ra, offset, req_size, max))
		goto readit;

	/*
	 * standalone, small random read
	 * Read as is, and do not pollute the readahead state.
	 */
	//这里预读
	return __do_page_cache_readahead(mapping, filp, offset, req_size, 0);

initial_readahead://第一次读文件走这里
    //本轮for循环要读取文件页page索引，预读的第一个文件页索引
	ra->start = offset;
    //根据最大预读page数max调整预读总page数，并赋于ra->size
	ra->size = get_init_ra_size(req_size, max);//req_size的4倍
    /*如果预读总page数ra->size大于还剩余没读取的文件页page数req_size，则ra->async_size被赋值二者差值，否则被赋值ra->size.。什么情况
    ra->size大于req_size，目前发现发生在同步预读时。比如read读取文件第一执行到do_generic_file_read....->ondemand_readahead，req_size=16，
    ra->size在这里是64，则ra->async_size=64-16=48。之后将会预读64个page，但是page0~page15是本次read实际要读取的文件页数据，
    page16~page63是才是本次真正预读的page数。所以我的理解是，ra->async_size表示真正预读的page数，ra->size表示预读窗口的page数。如果是
    异步预读则ra->async_size=ra->size，如果是同步预读则ra->async_size=ra->size-req_size。同步预读时，预读窗口的文件页page与本次读取文件
    的page文件页有重叠，异步预读二者没重叠*/
	ra->async_size = ra->size > req_size ? ra->size - req_size : ra->size;

readit:
	/*
	 * Will this read hit the readahead marker made by itself?
	 * If so, trigger the readahead marker hit now, and merge
	 * the resulted next readahead window into the current one.
	 */
	//本次要实际读取的文件页page索引offset等于预读窗口的起始page索引?一般情况应该不成立，二般情况成立
	if (offset == ra->start && ra->size == ra->async_size) {
		ra->async_size = get_next_ra_size(ra, max);
		ra->size += ra->async_size;
	}

    //这里实际完成page预读
	return ra_submit(ra, mapping, filp);
}

/**
 * page_cache_sync_readahead - generic file readahead
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @filp: passed on to ->readpage() and ->readpages()
 * @offset: start offset into @mapping, in pagecache page-sized units
 * @req_size: hint: total size of the read which the caller is performing in
 *            pagecache pages
 *
 * page_cache_sync_readahead() should be called when a cache miss happened:
 * it will submit the read.  The readahead logic may decide to piggyback more
 * pages onto the read request if access patterns suggest it will improve
 * performance.
 */
void page_cache_sync_readahead(struct address_space *mapping,
			       struct file_ra_state *ra, struct file *filp,
			       pgoff_t offset, unsigned long req_size)
{
	/* no read-ahead */
	if (!ra->ra_pages)
		return;

	/* be dumb */
	if (filp && (filp->f_mode & FMODE_RANDOM)) {
		force_page_cache_readahead(mapping, filp, offset, req_size);
		return;
	}

	/* do read-ahead */
	ondemand_readahead(mapping, ra, filp, false, offset, req_size);
}
EXPORT_SYMBOL_GPL(page_cache_sync_readahead);

/**
 * page_cache_async_readahead - file readahead for marked pages
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @filp: passed on to ->readpage() and ->readpages()
 * @page: the page at @offset which has the PG_readahead flag set
 * @offset: start offset into @mapping, in pagecache page-sized units
 * @req_size: hint: total size of the read which the caller is performing in
 *            pagecache pages
 *
 * page_cache_async_readahead() should be called when a page is used which
 * has the PG_readahead flag; this is a marker to suggest that the application
 * has used up enough of the readahead window that we should start pulling in
 * more pages.
 */
void
page_cache_async_readahead(struct address_space *mapping,
			   struct file_ra_state *ra, struct file *filp,
			   struct page *page, pgoff_t offset,
			   unsigned long req_size)
{
	/* no read-ahead */
	if (!ra->ra_pages)
		return;

	/*
	 * Same bit is used for PG_readahead and PG_reclaim.
	 */
	if (PageWriteback(page))//page不能在脏页回写
		return;

	ClearPageReadahead(page);//清除page预读标记

	/*
	 * Defer asynchronous read-ahead on IO congestion.
	 */
	if (bdi_read_congested(mapping->backing_dev_info))//不能bdi拥堵
		return;

	/* do read-ahead */
	ondemand_readahead(mapping, ra, filp, true, offset, req_size);
}
EXPORT_SYMBOL_GPL(page_cache_async_readahead);

static ssize_t
do_readahead(struct address_space *mapping, struct file *filp,
	     pgoff_t index, unsigned long nr)
{
	if (!mapping || !mapping->a_ops || !mapping->a_ops->readpage)
		return -EINVAL;

	force_page_cache_readahead(mapping, filp, index, nr);
	return 0;
}

SYSCALL_DEFINE3(readahead, int, fd, loff_t, offset, size_t, count)
{
	ssize_t ret;
	struct fd f;

	ret = -EBADF;
	f = fdget(fd);
	if (f.file) {
		if (f.file->f_mode & FMODE_READ) {
			struct address_space *mapping = f.file->f_mapping;
			pgoff_t start = offset >> PAGE_CACHE_SHIFT;
			pgoff_t end = (offset + count - 1) >> PAGE_CACHE_SHIFT;
			unsigned long len = end - start + 1;
			ret = do_readahead(mapping, f.file, start, len);
		}
		fdput(f);
	}
	return ret;
}
