#include <linux/fs.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <linux/quicklist.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include "internal.h"

void __attribute__((weak)) arch_report_meminfo(struct seq_file *m)
{
}

/*新添加的系统available内存计算*/
//available内存=(free内存-系统预留内存)+(pagecache-内存zone水位值累加page)+可回收slab内存。当free内存很少，系统预留内存很大，
//会出现availabel内存比free内存还小。free内存并不是全都可分配，要减去系统预留内存才是吧?????????
long si_mem_available(void)
{
        long available;
        unsigned long pagecache;
        unsigned long wmark_low = 0;
        unsigned long pages[NR_LRU_LISTS];
        struct zone *zone;
        int lru;

        //先统计各个内存page数到pages[lru]数组
        for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
                pages[lru] = global_page_state(NR_LRU_BASE + lru);

        //wmark_low累加各个内存zone low水位值page数
        for_each_zone(zone)
                wmark_low += zone->watermark[WMARK_LOW];

        /*
         * Estimate the amount of memory available for userspace allocations,
         * without causing swapping.
         */
        //available内存来源1:free page-系统预留内存
        available = global_page_state(NR_FREE_PAGES) - totalreserve_pages;

        /*
         * Not all the page cache can be freed, otherwise the system will
         * start swapping. Assume at least half of the page cache, or the
         * low watermark worth of cache, needs to stay.
         */
        pagecache = pages[LRU_ACTIVE_FILE] + pages[LRU_INACTIVE_FILE];
        pagecache -= min(pagecache / 2, wmark_low);//正常情况wmark_low更小
        //available内存来源2:pagecache-min(pagecache/2,各内存zone内存水位值累加)
        available += pagecache;

        /*
         * Part of the reclaimable slab consists of items that are in use,
         * and cannot be freed. Cap this estimate at the low watermark.
         */
        //available内存来源3:slab可回收内存-min(slab可回收内存page/2,各内存zone内存水位值累加)
        available += global_page_state(NR_SLAB_RECLAIMABLE) -
                     min(global_page_state(NR_SLAB_RECLAIMABLE) / 2, wmark_low);

        if (available < 0)
                available = 0;
        return available;
}
EXPORT_SYMBOL_GPL(si_mem_available);

static int meminfo_proc_show(struct seq_file *m, void *v)
{
	struct sysinfo i;
	unsigned long committed;
	unsigned long allowed;
	struct vmalloc_info vmi;
	long cached;
	unsigned long pages[NR_LRU_LISTS];
	int lru;

/*
 * display in kilobytes.
 */
#define K(x) ((x) << (PAGE_SHIFT - 10))
	si_meminfo(&i);//获取i.totalram、i.freeram、i.bufferram等信息
	si_swapinfo(&i);//swap信息
	committed = percpu_counter_read_positive(&vm_committed_as);
	allowed = ((totalram_pages - hugetlb_total_pages())
		* sysctl_overcommit_ratio / 100) + total_swap_pages;

	cached = global_page_state(NR_FILE_PAGES) -
			total_swapcache_pages() - i.bufferram;
	if (cached < 0)
		cached = 0;

    //基于vmalloc映射的虚拟空间计算出vmalloc消耗的物理内存总数
	get_vmalloc_info(&vmi);

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_page_state(NR_LRU_BASE + lru);

	/*
	 * Tagged format, for easy grepping and expansion.
	 */
	seq_printf(m,
		"MemTotal:       %8lu kB\n"//i.totalram
		"MemFree:        %8lu kB\n"//i.freeram
		"Buffers:        %8lu kB\n"//i.bufferram
		"Cached:         %8lu kB\n"//cached
		"SwapCached:     %8lu kB\n"//total_swapcache_pages()
		"Active:         %8lu kB\n"//pages[LRU_ACTIVE_ANON]   + pages[LRU_ACTIVE_FILE]
		"Inactive:       %8lu kB\n"//pages[LRU_INACTIVE_ANON] + pages[LRU_INACTIVE_FILE]
		"Active(anon):   %8lu kB\n"//pages[LRU_ACTIVE_ANON]
		"Inactive(anon): %8lu kB\n"//pages[LRU_INACTIVE_ANON]
		"Active(file):   %8lu kB\n"//pages[LRU_ACTIVE_FILE]
		"Inactive(file): %8lu kB\n"//pages[LRU_INACTIVE_FILE]
		"Unevictable:    %8lu kB\n"//pages[LRU_UNEVICTABLE]
		"Mlocked:        %8lu kB\n"//global_page_state(NR_MLOCK)
#ifdef CONFIG_HIGHMEM
		"HighTotal:      %8lu kB\n"//i.totalhigh
		"HighFree:       %8lu kB\n"//i.freehigh
		"LowTotal:       %8lu kB\n"//i.totalram-i.totalhigh
		"LowFree:        %8lu kB\n"//i.freeram-i.freehigh
#endif
#ifndef CONFIG_MMU
		"MmapCopy:       %8lu kB\n"//(unsigned long) atomic_long_read(&mmap_pages_allocated)
#endif
		"SwapTotal:      %8lu kB\n"//i.totalswap
		"SwapFree:       %8lu kB\n"//i.freeswap
		"Dirty:          %8lu kB\n"//global_page_state(NR_FILE_DIRTY)
		"Writeback:      %8lu kB\n"//global_page_state(NR_WRITEBACK)
		"AnonPages:      %8lu kB\n"//global_page_state(NR_ANON_PAGES)
		"Mapped:         %8lu kB\n"//global_page_state(NR_FILE_MAPPED)
		"Shmem:          %8lu kB\n"//global_page_state(NR_SHMEM)
		"Slab:           %8lu kB\n"//global_page_state(NR_SLAB_RECLAIMABLE) +global_page_state(NR_SLAB_UNRECLAIMABLE)
		"SReclaimable:   %8lu kB\n"//global_page_state(NR_SLAB_RECLAIMABLE)
		"SUnreclaim:     %8lu kB\n"//global_page_state(NR_SLAB_UNRECLAIMABLE)
		"KernelStack:    %8lu kB\n"//global_page_state(NR_KERNEL_STACK) * THREAD_SIZE / 1024
		"PageTables:     %8lu kB\n"//global_page_state(NR_PAGETABLE)
#ifdef CONFIG_QUICKLIST
		"Quicklists:     %8lu kB\n"//quicklist_total_size()
#endif
		"NFS_Unstable:   %8lu kB\n"//global_page_state(NR_UNSTABLE_NFS)
		"Bounce:         %8lu kB\n"//global_page_state(NR_BOUNCE)
		"WritebackTmp:   %8lu kB\n"//global_page_state(NR_WRITEBACK_TEMP)
		"CommitLimit:    %8lu kB\n"//allowed
		"Committed_AS:   %8lu kB\n"//committed
		"VmallocTotal:   %8lu kB\n"//(unsigned long)VMALLOC_TOTAL >> 10
		"VmallocUsed:    %8lu kB\n"//vmi.used >> 10
		"VmallocChunk:   %8lu kB\n"//vmi.largest_chunk >> 10
#ifdef CONFIG_MEMORY_FAILURE
		"HardwareCorrupted: %5lu kB\n"//atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10)
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		"AnonHugePages:  %8lu kB\n"//global_page_state(NR_ANON_TRANSPARENT_HUGEPAGES) *HPAGE_PMD_NR
#endif
		,
		K(i.totalram),
		K(i.freeram),
		K(i.bufferram),
		K(cached),
		K(total_swapcache_pages()),
		K(pages[LRU_ACTIVE_ANON]   + pages[LRU_ACTIVE_FILE]),
		K(pages[LRU_INACTIVE_ANON] + pages[LRU_INACTIVE_FILE]),
		K(pages[LRU_ACTIVE_ANON]),
		K(pages[LRU_INACTIVE_ANON]),
		K(pages[LRU_ACTIVE_FILE]),
		K(pages[LRU_INACTIVE_FILE]),
		K(pages[LRU_UNEVICTABLE]),
		K(global_page_state(NR_MLOCK)),
#ifdef CONFIG_HIGHMEM
		K(i.totalhigh),
		K(i.freehigh),
		K(i.totalram-i.totalhigh),
		K(i.freeram-i.freehigh),
#endif
#ifndef CONFIG_MMU
		K((unsigned long) atomic_long_read(&mmap_pages_allocated)),
#endif
		K(i.totalswap),
		K(i.freeswap),
		K(global_page_state(NR_FILE_DIRTY)),
		K(global_page_state(NR_WRITEBACK)),
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		K(global_page_state(NR_ANON_PAGES)
		  + global_page_state(NR_ANON_TRANSPARENT_HUGEPAGES) *
		  HPAGE_PMD_NR),
#else
		K(global_page_state(NR_ANON_PAGES)),
#endif
		K(global_page_state(NR_FILE_MAPPED)),
		K(global_page_state(NR_SHMEM)),
		K(global_page_state(NR_SLAB_RECLAIMABLE) +
				global_page_state(NR_SLAB_UNRECLAIMABLE)),
		K(global_page_state(NR_SLAB_RECLAIMABLE)),
		K(global_page_state(NR_SLAB_UNRECLAIMABLE)),
		global_page_state(NR_KERNEL_STACK) * THREAD_SIZE / 1024,
		K(global_page_state(NR_PAGETABLE)),
#ifdef CONFIG_QUICKLIST
		K(quicklist_total_size()),
#endif
		K(global_page_state(NR_UNSTABLE_NFS)),
		K(global_page_state(NR_BOUNCE)),
		K(global_page_state(NR_WRITEBACK_TEMP)),
		K(allowed),
		K(committed),
		(unsigned long)VMALLOC_TOTAL >> 10,
		vmi.used >> 10,
		vmi.largest_chunk >> 10
#ifdef CONFIG_MEMORY_FAILURE
		,atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10)
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		,K(global_page_state(NR_ANON_TRANSPARENT_HUGEPAGES) *
		   HPAGE_PMD_NR)
#endif
		);

	hugetlb_report_meminfo(m);

	arch_report_meminfo(m);

	return 0;
#undef K
}

static int meminfo_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, meminfo_proc_show, NULL);
}

static const struct file_operations meminfo_proc_fops = {
	.open		= meminfo_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_meminfo_init(void)
{
	proc_create("meminfo", 0, NULL, &meminfo_proc_fops);
	return 0;
}
module_init(proc_meminfo_init);
