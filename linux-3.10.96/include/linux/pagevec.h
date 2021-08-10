/*
 * include/linux/pagevec.h
 *
 * In many places it is efficient to batch an operation up against multiple
 * pages.  A pagevec is a multipage container which is used for that.
 */

#ifndef _LINUX_PAGEVEC_H
#define _LINUX_PAGEVEC_H

/* 14 pointers + two long's align the pagevec structure to a power of two */
#define PAGEVEC_SIZE	14

struct page;
struct address_space;

//代表本地cpu lru缓存，page添加active/inactive file/anon lru链表时，总是先添加到本地cpu lru缓存，添加够PAGEVEC_SIZE个
//再把这些page按照它的active/inactive file/anon属性添加到内存zone的active/inactive file/anon lru链表
//pagevec的类型有lru_add_pvecs lru_rotate_pvecs lru_deactivate_pvecs，见mm/swap.c
struct pagevec {
	unsigned long nr;//表示当前lru缓存保存了多少个page，见pagevec_add
	unsigned long cold;
    //lru缓存中的page存放在该pages[]数组
	struct page *pages[PAGEVEC_SIZE];
};

void __pagevec_release(struct pagevec *pvec);
void __pagevec_lru_add(struct pagevec *pvec, enum lru_list lru);
unsigned pagevec_lookup(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t start, unsigned nr_pages);
unsigned pagevec_lookup_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, int tag,
		unsigned nr_pages);

static inline void pagevec_init(struct pagevec *pvec, int cold)
{
	pvec->nr = 0;
	pvec->cold = cold;
}

static inline void pagevec_reinit(struct pagevec *pvec)
{
	pvec->nr = 0;
}

static inline unsigned pagevec_count(struct pagevec *pvec)
{
	return pvec->nr;
}
//pvec->nr表示当前lru缓存保存了多少个page，PAGEVEC_SIZE - pvec->nr表示lru缓存中还可以保存多少个page
static inline unsigned pagevec_space(struct pagevec *pvec)
{
	return PAGEVEC_SIZE - pvec->nr;
}

/*
 * Add a page to a pagevec.  Returns the number of slots still available.
 */
static inline unsigned pagevec_add(struct pagevec *pvec, struct page *page)
{
	pvec->pages[pvec->nr++] = page;
	return pagevec_space(pvec);
}

static inline void pagevec_release(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_release(pvec);
}

static inline void __pagevec_lru_add_anon(struct pagevec *pvec)
{
	__pagevec_lru_add(pvec, LRU_INACTIVE_ANON);
}

static inline void __pagevec_lru_add_active_anon(struct pagevec *pvec)
{
	__pagevec_lru_add(pvec, LRU_ACTIVE_ANON);
}

static inline void __pagevec_lru_add_file(struct pagevec *pvec)
{
	__pagevec_lru_add(pvec, LRU_INACTIVE_FILE);
}

static inline void __pagevec_lru_add_active_file(struct pagevec *pvec)
{
	__pagevec_lru_add(pvec, LRU_ACTIVE_FILE);
}

static inline void pagevec_lru_add_file(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_lru_add_file(pvec);
}

static inline void pagevec_lru_add_anon(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_lru_add_anon(pvec);
}

#endif /* _LINUX_PAGEVEC_H */
