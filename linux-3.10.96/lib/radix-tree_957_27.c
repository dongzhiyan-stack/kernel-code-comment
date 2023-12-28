/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2005 SGI, Christoph Lameter
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2012 Konstantin Khlebnikov
 * Copyright (C) 2016 Intel, Matthew Wilcox
 * Copyright (C) 2016 Intel, Ross Zwisler
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/radix-tree.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/string.h>
#include <linux/bitops.h>
#include <linux/rcupdate.h>
#include <linux/preempt_mask.h>		/* in_interrupt() */


/* Number of nodes in fully populated tree of given height */
static unsigned long height_to_maxnodes[RADIX_TREE_MAX_PATH + 1] __read_mostly;

/*
 * Radix tree node cache.
 */
static struct kmem_cache *radix_tree_node_cachep;

/*
 * The radix tree is variable-height, so an insert operation not only has
 * to build the branch to its corresponding item, it also has to build the
 * branch to existing items if the size has to be increased (by
 * radix_tree_extend).
 *
 * The worst case is a zero height tree with just a single item at index 0,
 * and then inserting an item at index ULONG_MAX. This requires 2 new branches
 * of RADIX_TREE_MAX_PATH size to be created, with only the root node shared.
 * Hence:
 */
#define RADIX_TREE_PRELOAD_SIZE (RADIX_TREE_MAX_PATH * 2 - 1)

/*
 * Per-cpu pool of preloaded nodes
 */
struct radix_tree_preload {
	unsigned nr;
	/* nodes->private_data points to next preallocated node */
	struct radix_tree_node *nodes;
};
static DEFINE_PER_CPU(struct radix_tree_preload, radix_tree_preloads) = { 0, };

static inline void *node_to_entry(void *ptr)
{
	return (void *)((unsigned long)ptr | RADIX_TREE_INTERNAL_NODE);
}

#define RADIX_TREE_RETRY	node_to_entry(NULL)

#ifdef CONFIG_RADIX_TREE_MULTIORDER//yes
/* Sibling slots point directly to another slot in the same node */
static inline bool is_sibling_entry(struct radix_tree_node *parent, void *node)
{
	void **ptr = node;
	return (parent->slots <= ptr) &&
			(ptr < parent->slots + RADIX_TREE_MAP_SIZE);
}
#else
static inline bool is_sibling_entry(struct radix_tree_node *parent, void *node)
{
	return false;
}
#endif

static inline unsigned long get_slot_offset(struct radix_tree_node *parent,
						 void **slot)
{
	return slot - parent->slots;
}
/*
这里举例，每个page是按照page->index索引插入到radix tree，以两层radix tree为例。
root radix_tree_node->slots[0]指向的子radix_tree_node的slots[0~63]保存page->index是0~63的page对象指针,
root radix_tree_node->slots[1]指向的子radix_tree_node的slots[0~63]保存page->index是64~(64*2-1)的page对象指针,其他类推。

当page->index是64*16+13，计算下来是要把page指针插入root radix_tree_node->slots[16]指向的子节点radix_tree_node的slots[13]。
radix_tree_descend 函数就是负责这个过程的计算。第1次执行该函数，parent指向rootradix_tree_node， parent->shift是6，
,则 offset = (64*16+13)>>6=16,entry=root radix_tree_node->slots[16]，计算出该page保存在root radix_tree_node的那个子节点
child radix_tree_node。

第2次执行该函数,parent就是上一步子节点child radix_tree_node，parent->shift是0，offset=(64*16+13)>>0 &RADIX_TREE_MAP_MASK=13，
entry = child radix_tree_node->slots[13]，配个指针就是要保存在child radix_tree_node->slots[13]

说到底，radix tree要插入一个page，把page插入哪里由page->index唯一决定,并且要从radix tree的root radix_tree_node开始向下搜索，
如果radix tree 2层，则root radix_tree_node->shift=6，计算出root radix_tree_node->slots[page->index>>6]这个child radix_tree_node，
child radix_tree_node->shift=0，child radix_tree_node->slots[(page->index>>6) & RADIX_TREE_MAP_MASK]就是该page指针要保存的位置。

进一步总结，root radix_tree_node->slots[page->index高6位]是该page保存子child radix_tree_node，
            child radix_tree_node[page->index低6位]是该page指针实际保存的位置
page->index的高6位决定了该page保存在root radix_tree_node哪个子radix_tree_node，page->index的低6位决定该page指针在这个子radix_tree_node的保存位置。

如果radix tree是3层，root radix_tree_node->shift=12，
root radix_tree_node->slots[page->index高12位]是该page保存的1阶child radix_tree_node
1阶child radix_tree_node->slots[page->index高6位]是该page保存的2阶child radix_tree_node
2阶child radix_tree_node->slots[page->index低6位]是该page指针在2阶child radix_tree_node的保存位置

举例子就行，不要只顾着想
*/
static unsigned int radix_tree_descend(struct radix_tree_node *parent,
			struct radix_tree_node **nodep, unsigned long index)
{
    //根据插入对象的索引index
	unsigned int offset = (index >> parent->shift) & RADIX_TREE_MAP_MASK;
    //entry不就是保存的page指针值
	void **entry = rcu_dereference_raw(parent->slots[offset]);

#ifdef CONFIG_RADIX_TREE_MULTIORDER//yes
    //entry的bit0是1则返回1，否则返回0
	if (radix_tree_is_internal_node(entry)) {
		if (is_sibling_entry(parent, entry)) {
			void **sibentry = (void **) entry_to_node(entry);
			offset = get_slot_offset(parent, sibentry);
			entry = rcu_dereference_raw(*sibentry);
		}
	}
#endif

	*nodep = (void *)entry;
	return offset;
}

static inline gfp_t root_gfp_mask(struct radix_tree_root *root)
{
	return root->gfp_mask & __GFP_BITS_MASK;
}

static inline void tag_set(struct radix_tree_node *node, unsigned int tag,
		int offset)
{
	__set_bit(offset, node->tags[tag]);
}

static inline void tag_clear(struct radix_tree_node *node, unsigned int tag,
		int offset)
{
	__clear_bit(offset, node->tags[tag]);
}

static inline int tag_get(struct radix_tree_node *node, unsigned int tag,
		int offset)
{
	return test_bit(offset, node->tags[tag]);
}

static inline void root_tag_set(struct radix_tree_root *root, unsigned int tag)
{
	root->gfp_mask |= (__force gfp_t)(1 << (tag + __GFP_BITS_SHIFT));
}

static inline void root_tag_clear(struct radix_tree_root *root, unsigned tag)
{
	root->gfp_mask &= (__force gfp_t)~(1 << (tag + __GFP_BITS_SHIFT));
}

static inline void root_tag_clear_all(struct radix_tree_root *root)
{
	root->gfp_mask &= __GFP_BITS_MASK;
}

static inline int root_tag_get(struct radix_tree_root *root, unsigned int tag)
{
	return (__force int)root->gfp_mask & (1 << (tag + __GFP_BITS_SHIFT));
}

static inline unsigned root_tags_get(struct radix_tree_root *root)
{
	return (__force unsigned)root->gfp_mask >> __GFP_BITS_SHIFT;
}

/*
 * Returns 1 if any slot in the node has this tag set.
 * Otherwise returns 0.
 */
static inline int any_tag_set(struct radix_tree_node *node, unsigned int tag)
{
	unsigned idx;
	for (idx = 0; idx < RADIX_TREE_TAG_LONGS; idx++) {
		if (node->tags[tag][idx])
			return 1;
	}
	return 0;
}

/**
 * radix_tree_find_next_bit - find the next set bit in a memory region
 *
 * @addr: The address to base the search on
 * @size: The bitmap size in bits
 * @offset: The bitnumber to start searching at
 *
 * Unrollable variant of find_next_bit() for constant size arrays.
 * Tail bits starting from size to roundup(size, BITS_PER_LONG) must be zero.
 * Returns next bit offset, or size if nothing found.
 */
static __always_inline unsigned long
radix_tree_find_next_bit(const unsigned long *addr,
			 unsigned long size, unsigned long offset)
{
	if (!__builtin_constant_p(size))
		return find_next_bit(addr, size, offset);

	if (offset < size) {
		unsigned long tmp;

		addr += offset / BITS_PER_LONG;
		tmp = *addr >> (offset % BITS_PER_LONG);
		if (tmp)
			return __ffs(tmp) + offset;
		offset = (offset + BITS_PER_LONG) & ~(BITS_PER_LONG - 1);
		while (offset < size) {
			tmp = *++addr;
			if (tmp)
				return __ffs(tmp) + offset;
			offset += BITS_PER_LONG;
		}
	}
	return size;
}

#ifndef __KERNEL__
static void dump_node(struct radix_tree_node *node, unsigned long index)
{
	unsigned long i;

	pr_debug("radix node: %p offset %d tags %lx %lx %lx shift %d count %d parent %p\n",
		node, node->offset,
		node->tags[0][0], node->tags[1][0], node->tags[2][0],
		node->shift, node->count, node->parent);

	for (i = 0; i < RADIX_TREE_MAP_SIZE; i++) {
		unsigned long first = index | (i << node->shift);
		unsigned long last = first | ((1UL << node->shift) - 1);
		void *entry = node->slots[i];
		if (!entry)
			continue;
		if (is_sibling_entry(node, entry)) {
			pr_debug("radix sblng %p offset %ld val %p indices %ld-%ld\n",
					entry, i,
					*(void **)entry_to_node(entry),
					first, last);
		} else if (!radix_tree_is_internal_node(entry)) {
			pr_debug("radix entry %p offset %ld indices %ld-%ld\n",
					entry, i, first, last);
		} else {
			dump_node(entry_to_node(entry), first);
		}
	}
}

/* For debug */
static void radix_tree_dump(struct radix_tree_root *root)
{
	pr_debug("radix root: %p rnode %p tags %x\n",
			root, root->rnode,
			root->gfp_mask >> __GFP_BITS_SHIFT);
	if (!radix_tree_is_internal_node(root->rnode))
		return;
	dump_node(entry_to_node(root->rnode), 0);
}
#endif

/*
 * This assumes that the caller has performed appropriate preallocation, and
 * that the caller has pinned this thread of control to the current CPU.
 */
static struct radix_tree_node *
radix_tree_node_alloc(struct radix_tree_root *root)
{
	struct radix_tree_node *ret = NULL;
	gfp_t gfp_mask = root_gfp_mask(root);

	/*
	 * Preload code isn't irq safe and it doesn't make sense to use
	 * preloading during an interrupt anyway as all the allocations have
	 * to be atomic. So just do normal allocation when in interrupt.
	 */
	if (!(gfp_mask & __GFP_WAIT) && !in_interrupt()) {
		struct radix_tree_preload *rtp;

		/*
		 * Provided the caller has preloaded here, we will always
		 * succeed in getting a node here (and never reach
		 * kmem_cache_alloc)
		 */
		rtp = this_cpu_ptr(&radix_tree_preloads);
		if (rtp->nr) {
			ret = rtp->nodes;
			rtp->nodes = ret->private_data;
			ret->private_data = NULL;
			rtp->nr--;
		}
	}
	if (ret == NULL)
		ret = kmem_cache_alloc(radix_tree_node_cachep, gfp_mask);

	BUG_ON(radix_tree_is_internal_node(ret));
	return ret;
}

static void radix_tree_node_rcu_free(struct rcu_head *head)
{
	struct radix_tree_node *node =
			container_of(head, struct radix_tree_node, rcu_head);
	int i;

	/*
	 * must only free zeroed nodes into the slab. radix_tree_shrink
	 * can leave us with a non-NULL entry in the first slot, so clear
	 * that here to make sure.
	 */
	for (i = 0; i < RADIX_TREE_MAX_TAGS; i++)
		tag_clear(node, i, 0);

	node->slots[0] = NULL;
	node->count = 0;

	kmem_cache_free(radix_tree_node_cachep, node);
}

static inline void
radix_tree_node_free(struct radix_tree_node *node)
{
	call_rcu(&node->rcu_head, radix_tree_node_rcu_free);
}

/*
 * Load up this CPU's radix_tree_node buffer with sufficient objects to
 * ensure that the addition of a single element in the tree cannot fail.  On
 * success, return zero, with preemption disabled.  On error, return -ENOMEM
 * with preemption not disabled.
 *
 * To make use of this facility, the radix tree must be initialised without
 * __GFP_WAIT being passed to INIT_RADIX_TREE().
 */
static int __radix_tree_preload(gfp_t gfp_mask, int nr)
{
	struct radix_tree_preload *rtp;
	struct radix_tree_node *node;
	int ret = -ENOMEM;

	preempt_disable();
	rtp = this_cpu_ptr(&radix_tree_preloads);
	while (rtp->nr < nr) {
		preempt_enable();
		node = kmem_cache_alloc(radix_tree_node_cachep, gfp_mask);
		if (node == NULL)
			goto out;
		preempt_disable();
		rtp = this_cpu_ptr(&radix_tree_preloads);
		if (rtp->nr < nr) {
			node->private_data = rtp->nodes;
			rtp->nodes = node;
			rtp->nr++;
		} else {
			kmem_cache_free(radix_tree_node_cachep, node);
		}
	}
	ret = 0;
out:
	return ret;
}

/*
 * Load up this CPU's radix_tree_node buffer with sufficient objects to
 * ensure that the addition of a single element in the tree cannot fail.  On
 * success, return zero, with preemption disabled.  On error, return -ENOMEM
 * with preemption not disabled.
 *
 * To make use of this facility, the radix tree must be initialised without
 * __GFP_WAIT being passed to INIT_RADIX_TREE().
 */
int radix_tree_preload(gfp_t gfp_mask)
{
	/* Warn on non-sensical use... */
	WARN_ON_ONCE(!(gfp_mask & __GFP_WAIT));
	return __radix_tree_preload(gfp_mask, RADIX_TREE_PRELOAD_SIZE);
}
EXPORT_SYMBOL(radix_tree_preload);

/*
 * The same as above function, except we don't guarantee preloading happens.
 * We do it, if we decide it helps. On success, return zero with preemption
 * disabled. On error, return -ENOMEM with preemption not disabled.
 */
int radix_tree_maybe_preload(gfp_t gfp_mask)
{
	if (gfp_mask & __GFP_WAIT)
		return __radix_tree_preload(gfp_mask, RADIX_TREE_PRELOAD_SIZE);
	/* Preloading doesn't help anything with this gfp mask, skip it */
	preempt_disable();
	return 0;
}
EXPORT_SYMBOL(radix_tree_maybe_preload);

/*
 * The same as function above, but preload number of nodes required to insert
 * (1 << order) continuous naturally-aligned elements.
 */
int radix_tree_maybe_preload_order(gfp_t gfp_mask, int order)
{
	unsigned long nr_subtrees;
	int nr_nodes, subtree_height;

	/* Preloading doesn't help anything with this gfp mask, skip it */
	if (!(gfp_mask & __GFP_WAIT)) {
		preempt_disable();
		return 0;
	}

	/*
	 * Calculate number and height of fully populated subtrees it takes to
	 * store (1 << order) elements.
	 */
	nr_subtrees = 1 << order;
	for (subtree_height = 0; nr_subtrees > RADIX_TREE_MAP_SIZE;
			subtree_height++)
		nr_subtrees >>= RADIX_TREE_MAP_SHIFT;

	/*
	 * The worst case is zero height tree with a single item at index 0 and
	 * then inserting items starting at ULONG_MAX - (1 << order).
	 *
	 * This requires RADIX_TREE_MAX_PATH nodes to build branch from root to
	 * 0-index item.
	 */
	nr_nodes = RADIX_TREE_MAX_PATH;

	/* Plus branch to fully populated subtrees. */
	nr_nodes += RADIX_TREE_MAX_PATH - subtree_height;

	/* Root node is shared. */
	nr_nodes--;

	/* Plus nodes required to build subtrees. */
	nr_nodes += nr_subtrees * height_to_maxnodes[subtree_height];

	return __radix_tree_preload(gfp_mask, nr_nodes);
}

/*
 * The maximum index which can be stored in a radix tree
 */
static inline unsigned long shift_maxindex(unsigned int shift)
{
	return (RADIX_TREE_MAP_SIZE << shift) - 1;//64 << shift - 1
}
//以当前节点为基准，它下边的最多能容纳多少page。如果node是根节点，这是当前radix tree能容纳的最大index
static inline unsigned long node_maxindex(struct radix_tree_node *node)
{
	return shift_maxindex(node->shift);
}
//获取根节点和该根radix_tree_node下能保存的对象个数
static unsigned radix_tree_load_root(struct radix_tree_root *root,
		struct radix_tree_node **nodep, unsigned long *maxindex)
{
    //获取根node
	struct radix_tree_node *node = rcu_dereference_raw(root->rnode);

	*nodep = node;

	if (likely(radix_tree_is_internal_node(node))) {
		node = entry_to_node(node);
        //获取该根节点node下能保存的page数减1，就是最大page索引数
		*maxindex = node_maxindex(node);
        //根节点的shfit+6
		return node->shift + RADIX_TREE_MAP_SHIFT;
	}

	*maxindex = 0;
	return 0;
}

/*
 *	Extend a radix tree so it can store key @index.
 */
/*举例，当radix tree原本1层，根节点是node0。最多能保存64个page，最大page索引63，node0的shift=0。现在要插入的page索引是65，
  显然radix tree空间不够，需要把radix tree扩大到2层，才能保存索引是65的page。
  
  radix_tree_extend()函数形参，index是本次要插入的page索引65，shift=根节点node的shift+6=6，shift_maxindex(maxshift)=64*64-1。
  radix_tree_extend()函数中，maxshift = shift=6，while (index > shift_maxindex(maxshift))不成立，则maxshift保持6
  slot = root->rnode就是node0。

  while循环里
  1:执行 node = radix_tree_node_alloc(root) 分配一个新的节点node1，它要取代老的根节点node0作为新的根节点，老的根节点node1作为node0
    子节点，保存在新的根节点node1的槽位0。此时radix tree增加了1层。
  2:执行node->shift = shift=6，node1要作为新的根节点，此时原本1层的radix tree变为2层，根节点node1的shift是6
  3:执行 entry_to_node(slot)->parent = node 令node0的parent指向node1。老的根节点node0要作为新的新的根节点的node1的
  4:node->slots[0] = slot，把老的根节点node1(slot)保存到新分配的根节点node1的槽位0
  5:rcu_assign_pointer(root->rnode, slot)，把新分配的根节点node1指针保存到root->rnode，真正作为根节点
  6:shift += RADIX_TREE_MAP_SHIFT=12，此时maxshift=6，则while (shift <= maxshift)不成立。
  
  整个过程核心就是循环一层层新增radix tree，直到radix tree能容纳索引是index的page
  */
static int radix_tree_extend(struct radix_tree_root *root,
				unsigned long index, unsigned int shift)
{
	struct radix_tree_node *slot;
	unsigned int maxshift;
	int tag;

	/* Figure out what the shift should be.  */
	maxshift = shift;
    //每执行一次maxshift += RADIX_TREE_MAP_SHIFT，则radix tree增加1层
	while (index > shift_maxindex(maxshift))
		maxshift += RADIX_TREE_MAP_SHIFT;//RADIX_TREE_MAP_SHIFT:6
    //slot默认指向根节点node
	slot = root->rnode;
	if (!slot)
		goto out;

    //到这里shift和maxshift的差值表示radix tree要增加的层数。比如差6，radix tree增加1层，差12则radix tree增加2层。
	do {
        //分配一个node，作为根节点。每次循环这里分配的节点都要成为新的根节点
		struct radix_tree_node *node = radix_tree_node_alloc(root);

		if (!node)
			return -ENOMEM;

		/* Propagate the aggregated tag info into the new root */
		for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++) {
			if (root_tag_get(root, tag))
				tag_set(node, tag, 0);
		}

		BUG_ON(shift > BITS_PER_LONG);
        //新分配的节点shift
		node->shift = shift;
        //节点在父节点的槽位中偏移是0
		node->offset = 0;
        //节点只有一个成员
		node->count = 1;
		node->parent = NULL;
        //第1次循环时，slot是老的根节点，但是node作为新分配的节点，就要作为新的根节点，这里是令node成为老的根节点的parent
        //第2次循环时，slot是第一次循环的分配的节点，此时它成了老的根节点,node是第2次循环分配新节点.这里是令第2次循环的分配的节点
        //node成为第1次循环的分配的节点node的parent
		if (radix_tree_is_internal_node(slot))
			entry_to_node(slot)->parent = node;
        
        //第1次循环时，slot是老的根节点，但是node作为新分配的节点，就要作为新的根节点，这里是把老的根节点保存到新的根节点的槽位0
        //第2次循环时，slot是第一次循环的分配的节点，此时它成了老的根节点。node是第2次循环分配新节点，这个节点要成为新的根节点
        //这里是把第1次循环分配的node指针保存到第2次循环分配的node的槽位0。往后的循环类推，反正每次分配的节点都要作为根节点!!!!!!
		node->slots[0] = slot;
        //node和slot此时是一回事
		slot = node_to_entry(node);
        //本次分配的新节点就是根节点，这里是把根节点的node指针保存到root->rnode
		rcu_assign_pointer(root->rnode, slot);//node和slot此时是一回事
		
		//shift +=6，每次加6表示radix tree增加一层，当shift > maxshift表示radix tree层数增加够了，可以容纳本次要插入page索引index了
		shift += RADIX_TREE_MAP_SHIFT;
	} while (shift <= maxshift);
out:
    //maxshift与radix tree层数有关，1层时是6，2层时是6*2，3层时是6*3。本质就是根节点的shift+6，多加了6。
	return maxshift + RADIX_TREE_MAP_SHIFT;
}

/**
 *	__radix_tree_create	-	create a slot in a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *	@order:		index occupies 2^order aligned slots
 *	@nodep:		returns node
 *	@slotp:		returns slot
 *
 *	Create, if necessary, and return the node and slot for an item
 *	at position @index in the radix tree @root.
 *
 *	Until there is more than one item in the tree, no nodes are
 *	allocated and @root->rnode is used as a direct slot instead of
 *	pointing to a node, in which case *@nodep will be NULL.
 *
 *	Returns -ENOMEM, or 0 for success.
 */
int __radix_tree_create(struct radix_tree_root *root, unsigned long index,
			unsigned order, struct radix_tree_node **nodep,//order一般是0
			void ***slotp)
{
	struct radix_tree_node *node = NULL, *child;
	void **slot = (void **)&root->rnode;
	unsigned long maxindex;
	unsigned int shift, offset = 0;
    //一般情况max=index
	unsigned long max = index | ((1UL << order) - 1);
    
    //获取根节点于child，并且计算该根radix_tree_node下能保存的对象个数减1保存到maxindex，也就是最大page数减1
    //返回值:radix tree是空是0。1层radix tree时是6，2层radix tree时是6*2，3层radix tree时是6*3。
	shift = radix_tree_load_root(root, &child, &maxindex);

	/* Make sure the tree is high enough.  */
    //本次保存对象的索引max,大于该radix_tree能保存的最大对象索引，需要执行radix_tree_extend()扩充radix_tree树
	if (max > maxindex) {
        //举例，当radix tree原本两层，最多能保存64*64=4096个page，最大page索引4095。现在要插入的page索引是4099，显然radix tree
        //空间不够，需要把radix tree扩大到3层，才能保存索引是4099的page。故这里max是本次要插入的page索引4099，maxindex是目前的
        //radix tree能容纳的最大page索引4095，shift是根节点node的shift+6=6*2
		int error = radix_tree_extend(root, max, shift);
		if (error < 0)
			return error;
		shift = error;
        //child这里指向根节点
		child = root->rnode;
		if (order == shift)
			shift += RADIX_TREE_MAP_SHIFT;
	}

    /*注意，到这里，1层radix tree时shift是6，2层radix tree时shift是6*2，3层radix tree时shift是6*3，
     这里的shift是radix tree的根节点node的shift+6!!!!!!!。如果此时radix tree 两层，现在查找索引是2的page指针，
     shift初值是6*2,child此时是根节点node0。第一次循环先有shift -= RADIX_TREE_MAP_SHIFT=6。if (child == NULL)不成立，
     node = entry_to_node(child)后，node是跟节点，offset = radix_tree_descend(node, &child, index)中
     执行offset = (index >> parent->shift)得到保存索引2的page的子节点node1在根节点node0的槽位0，此时parent是根节点，parent->shift是6，
     于是child=node1，返回值offset是0，表示node1保存在根节点node0的槽位0。随后执行的slot = &node->slots[offset]=&node0->slots[0]
     slot其实就是node1的地址。

     回到while循环，再次执行shift -= RADIX_TREE_MAP_SHIFT=0，child(node1)如果是null，说明node1还没有分配实际的radix_tree_node结构，
     那就执行radix_tree_node_alloc()分配。然后再执行offset = radix_tree_descend(node, &child, index)，在里边执行
     offset = (index >> parent->shift)=2 ，这是得到保存索引2的page的在node1的槽位2，此时parent是节点node1，parent->shift是0。
     offset时2说明要本次要查找的page指针保存在node1的槽位2。offset此时就是2，node是node1，slot = &node->slots[offset]是node1的槽位2
     的地址，里边保存了索引是2的page指针。
     
     继续，while (shift > order)不成立，因为此时shift是0，故查找结束
     */
    
    //而这个循环的意义就说从root radix_tree_node根节点开始，根据待插入对象的索引index
    //从上向下依次计算待插入对象相关联的每一层子radix_tree_node，直到找到保存待插入对象指针的最底层的radix_tree_node，
    //它是待插入对象的父radix_tree_node,就是循环里的node，循环里的slot指向的内存保存待插入对象指针。详细看radix_tree_descend()注释
	while (shift > order) {
        //shift -=6
		shift -= RADIX_TREE_MAP_SHIFT;//RADIX_TREE_MAP_SHIFT:6

        /*如果radix tree是空树，那此时child是NULL，第一层的节点是在这里分配的*/
		if (child == NULL) {//child为NULL说明需要分配一个节点
			/* Have to add a child node.  */
			child = radix_tree_node_alloc(root);//分配
			if (!child)
				return -ENOMEM;
			child->shift = shift;
			child->offset = offset;
			child->parent = node;
			rcu_assign_pointer(*slot, node_to_entry(child));
			if (node)
				node->count++;
		} else if (!radix_tree_is_internal_node(child))/*到这说明此时child是保存在radix tree最下层的节点的slot槽位的page指针*/
			break;

		/* Go a level down */
        //child的bit0清0赋值于node
		node = entry_to_node(child);
        //根据父radix_tree_node即node，和待插入对象的索引index，计算出子radix_tree_node或者待插入对象在父radix_tree_node->slots[]
        //数组的偏移offset，并赋值child=node->slots[offset]，再根据child的internal、sibentry属性摩擦child
		offset = radix_tree_descend(node, &child, index);
        //这里再计算出父node->slots[offset]保存的原生slot成员，radix_tree_descend计算出的child=node->slots[offset]还有其他处理，
		slot = &node->slots[offset];
	}

#ifdef CONFIG_RADIX_TREE_MULTIORDER//yes
	/* Insert pointers to the canonical entry */
	if (order > shift) {
		unsigned i, n = 1 << (order - shift);
		offset = offset & ~(n - 1);
		slot = &node->slots[offset];
		child = node_to_entry(slot);
		for (i = 0; i < n; i++) {
			if (slot[i])
				return -EEXIST;
		}

		for (i = 1; i < n; i++) {
			rcu_assign_pointer(slot[i], child);
			node->count++;
		}
	}
#endif

	if (nodep)
		*nodep = node;
	if (slotp)
		*slotp = slot;
	return 0;
}

/**
 *	__radix_tree_insert    -    insert into a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *	@order:		key covers the 2^order indices around index
 *	@item:		item to insert
 *
 *	Insert an item into the radix tree at position @index.
 */
int __radix_tree_insert(struct radix_tree_root *root, unsigned long index,
			unsigned order, void *item)//order一般是0
{
	struct radix_tree_node *node;
	void **slot;
	int error;

	BUG_ON(radix_tree_is_internal_node(item));
    //在radix tree中查找page，分配solt
	error = __radix_tree_create(root, index, order, &node, &slot);
	if (error)
		return error;
    //__radix_tree_create()执行后，根据待插入page(即item)的索引index在radix tree中找到它的槽位，即在radix_tree_node->slots[offset]
    //数组中的位置.radix_tree_node是父radix_tree_node，offset表示该page在radix_tree_node->slots[]数组中保存的位置。这里的slot指向
    //"插入page的在radix tree中找到它的槽位"内存地址，即slot=radix_tree_node->slots[offset]。
	if (*slot != NULL)
		return -EEXIST;//*slot正常是NULL，否则就说明已经有page在radix_tree_node->slots[offset]中保存了，则返回-EEXIST错误

    //把新的page保存，rcu操作，避免多进程同时写
	rcu_assign_pointer(*slot, item);

	if (node) {
		unsigned offset = get_slot_offset(node, slot);
		node->count++;
		BUG_ON(tag_get(node, 0, offset));
		BUG_ON(tag_get(node, 1, offset));
		BUG_ON(tag_get(node, 2, offset));
	} else {
		BUG_ON(root_tags_get(root));
	}

	return 0;
}
EXPORT_SYMBOL(__radix_tree_insert);

/***********来自linux-3.10.0-957.27.2.el7 include/linux/radix-tree.h***************************/
#define RADIX_TREE_ENTRY_MASK           3UL
#define RADIX_TREE_INTERNAL_NODE        1UL
//这里，把page插入radix tree-------这段源码原来很乱，有3.10.96的，也有957.27的，太乱了
static inline int radix_tree_insert(struct radix_tree_root *root,
                        unsigned long index, void *entry)
{
        return __radix_tree_insert(root, index, 0, entry);
}
static inline bool radix_tree_is_internal_node(void *ptr)
{
        //即(ptr&0x3) == 1，ptr的bit0是1则返回1，否则返回0
        return ((unsigned long)ptr & RADIX_TREE_ENTRY_MASK) ==
                                RADIX_TREE_INTERNAL_NODE;
}
/*****************************************************************/


/**
 *	__radix_tree_lookup	-	lookup an item in a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *	@nodep:		returns node
 *	@slotp:		returns slot
 *
 *	Lookup and return the item at position @index in the radix
 *	tree @root.
 *
 *	Until there is more than one item in the tree, no nodes are
 *	allocated and @root->rnode is used as a direct slot instead of
 *	pointing to a node, in which case *@nodep will be NULL.
 */
void *__radix_tree_lookup(struct radix_tree_root *root, unsigned long index,
			  struct radix_tree_node **nodep, void ***slotp)
{
	struct radix_tree_node *node, *parent;
	unsigned long maxindex;
	void **slot;

 restart:
	parent = NULL;
	slot = (void **)&root->rnode;
	radix_tree_load_root(root, &node, &maxindex);
	if (index > maxindex)
		return NULL;

	while (radix_tree_is_internal_node(node)) {
		unsigned offset;

		if (node == RADIX_TREE_RETRY)
			goto restart;
		parent = entry_to_node(node);
		offset = radix_tree_descend(parent, &node, index);
		slot = parent->slots + offset;
	}

	if (nodep)
		*nodep = parent;
	if (slotp)
		*slotp = slot;
	return node;
}

/**
 *	radix_tree_lookup_slot    -    lookup a slot in a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *
 *	Returns:  the slot corresponding to the position @index in the
 *	radix tree @root. This is useful for update-if-exists operations.
 *
 *	This function can be called under rcu_read_lock iff the slot is not
 *	modified by radix_tree_replace_slot, otherwise it must be called
 *	exclusive from other writers. Any dereference of the slot must be done
 *	using radix_tree_deref_slot.
 */
void **radix_tree_lookup_slot(struct radix_tree_root *root, unsigned long index)
{
	void **slot;

	if (!__radix_tree_lookup(root, index, NULL, &slot))
		return NULL;
	return slot;
}
EXPORT_SYMBOL(radix_tree_lookup_slot);

/**
 *	radix_tree_lookup    -    perform lookup operation on a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *
 *	Lookup the item at the position @index in the radix tree @root.
 *
 *	This function can be called under rcu_read_lock, however the caller
 *	must manage lifetimes of leaf nodes (eg. RCU may also be used to free
 *	them safely). No RCU barriers are required to access or modify the
 *	returned item, however.
 */
void *radix_tree_lookup(struct radix_tree_root *root, unsigned long index)
{
	return __radix_tree_lookup(root, index, NULL, NULL);
}
EXPORT_SYMBOL(radix_tree_lookup);

/**
 *	radix_tree_tag_set - set a tag on a radix tree node
 *	@root:		radix tree root
 *	@index:		index key
 *	@tag:		tag index
 *
 *	Set the search tag (which must be < RADIX_TREE_MAX_TAGS)
 *	corresponding to @index in the radix tree.  From
 *	the root all the way down to the leaf node.
 *
 *	Returns the address of the tagged item.  Setting a tag on a not-present
 *	item is a bug.
 */
void *radix_tree_tag_set(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	struct radix_tree_node *node, *parent;
	unsigned long maxindex;

	radix_tree_load_root(root, &node, &maxindex);
	BUG_ON(index > maxindex);

	while (radix_tree_is_internal_node(node)) {
		unsigned offset;

		parent = entry_to_node(node);
		offset = radix_tree_descend(parent, &node, index);
		BUG_ON(!node);

		if (!tag_get(parent, tag, offset))
			tag_set(parent, tag, offset);
	}

	/* set the root's tag bit */
	if (!root_tag_get(root, tag))
		root_tag_set(root, tag);

	return node;
}
EXPORT_SYMBOL(radix_tree_tag_set);

static void node_tag_clear(struct radix_tree_root *root,
				struct radix_tree_node *node,
				unsigned int tag, unsigned int offset)
{
	while (node) {
		if (!tag_get(node, tag, offset))
			return;
		tag_clear(node, tag, offset);
		if (any_tag_set(node, tag))
			return;

		offset = node->offset;
		node = node->parent;
	}

	/* clear the root's tag bit */
	if (root_tag_get(root, tag))
		root_tag_clear(root, tag);
}

/**
 *	radix_tree_tag_clear - clear a tag on a radix tree node
 *	@root:		radix tree root
 *	@index:		index key
 *	@tag:		tag index
 *
 *	Clear the search tag (which must be < RADIX_TREE_MAX_TAGS)
 *	corresponding to @index in the radix tree.  If this causes
 *	the leaf node to have no tags set then clear the tag in the
 *	next-to-leaf node, etc.
 *
 *	Returns the address of the tagged item on success, else NULL.  ie:
 *	has the same return value and semantics as radix_tree_lookup().
 */
void *radix_tree_tag_clear(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	struct radix_tree_node *node, *parent;
	unsigned long maxindex;
	int uninitialized_var(offset);

	radix_tree_load_root(root, &node, &maxindex);
	if (index > maxindex)
		return NULL;

	parent = NULL;

	while (radix_tree_is_internal_node(node)) {
		parent = entry_to_node(node);
		offset = radix_tree_descend(parent, &node, index);
	}

	if (node)
		node_tag_clear(root, parent, tag, offset);

	return node;
}
EXPORT_SYMBOL(radix_tree_tag_clear);

/**
 * radix_tree_tag_get - get a tag on a radix tree node
 * @root:		radix tree root
 * @index:		index key
 * @tag:		tag index (< RADIX_TREE_MAX_TAGS)
 *
 * Return values:
 *
 *  0: tag not present or not set
 *  1: tag set
 *
 * Note that the return value of this function may not be relied on, even if
 * the RCU lock is held, unless tag modification and node deletion are excluded
 * from concurrency.
 */
int radix_tree_tag_get(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	struct radix_tree_node *node, *parent;
	unsigned long maxindex;

	if (!root_tag_get(root, tag))
		return 0;

	radix_tree_load_root(root, &node, &maxindex);
	if (index > maxindex)
		return 0;
	if (node == NULL)
		return 0;

	while (radix_tree_is_internal_node(node)) {
		unsigned offset;

		parent = entry_to_node(node);
		offset = radix_tree_descend(parent, &node, index);

		if (!node)
			return 0;
		if (!tag_get(parent, tag, offset))
			return 0;
		if (node == RADIX_TREE_RETRY)
			break;
	}

	return 1;
}
EXPORT_SYMBOL(radix_tree_tag_get);

static inline void __set_iter_shift(struct radix_tree_iter *iter,
					unsigned int shift)
{
#ifdef CONFIG_RADIX_TREE_MULTIORDER
	iter->shift = shift;
#endif
}

/**
 * radix_tree_next_chunk - find next chunk of slots for iteration
 *
 * @root:	radix tree root
 * @iter:	iterator state
 * @flags:	RADIX_TREE_ITER_* flags and tag index
 * Returns:	pointer to chunk first slot, or NULL if iteration is over
 */
void **radix_tree_next_chunk(struct radix_tree_root *root,
			     struct radix_tree_iter *iter, unsigned flags)
{
	unsigned tag = flags & RADIX_TREE_ITER_TAG_MASK;
	struct radix_tree_node *node, *child;
	unsigned long index, offset, maxindex;

	if ((flags & RADIX_TREE_ITER_TAGGED) && !root_tag_get(root, tag))
		return NULL;

	/*
	 * Catch next_index overflow after ~0UL. iter->index never overflows
	 * during iterating; it can be zero only at the beginning.
	 * And we cannot overflow iter->next_index in a single step,
	 * because RADIX_TREE_MAP_SHIFT < BITS_PER_LONG.
	 *
	 * This condition also used by radix_tree_next_slot() to stop
	 * contiguous iterating, and forbid swithing to the next chunk.
	 */
	index = iter->next_index;
	if (!index && iter->index)
		return NULL;

 restart:
	radix_tree_load_root(root, &child, &maxindex);
	if (index > maxindex)
		return NULL;
	if (!child)
		return NULL;

	if (!radix_tree_is_internal_node(child)) {
		/* Single-slot tree */
		iter->index = index;
		iter->next_index = maxindex + 1;
		iter->tags = 1;
		__set_iter_shift(iter, 0);
		return (void **)&root->rnode;
	}

	do {
		node = entry_to_node(child);
		offset = radix_tree_descend(node, &child, index);

		if ((flags & RADIX_TREE_ITER_TAGGED) ?
				!tag_get(node, tag, offset) : !child) {
			/* Hole detected */
			if (flags & RADIX_TREE_ITER_CONTIG)
				return NULL;

			if (flags & RADIX_TREE_ITER_TAGGED)
				offset = radix_tree_find_next_bit(
						node->tags[tag],
						RADIX_TREE_MAP_SIZE,
						offset + 1);
			else
				while (++offset	< RADIX_TREE_MAP_SIZE) {
					void *slot = node->slots[offset];
					if (is_sibling_entry(node, slot))
						continue;
					if (slot)
						break;
				}
			index &= ~node_maxindex(node);
			index += offset << node->shift;
			/* Overflow after ~0UL */
			if (!index)
				return NULL;
			if (offset == RADIX_TREE_MAP_SIZE)
				goto restart;
			child = rcu_dereference_raw(node->slots[offset]);
		}

		if ((child == NULL) || (child == RADIX_TREE_RETRY))
			goto restart;
	} while (radix_tree_is_internal_node(child));

	/* Update the iterator state */
	iter->index = (index &~ node_maxindex(node)) | (offset << node->shift);
	iter->next_index = (index | node_maxindex(node)) + 1;
	__set_iter_shift(iter, node->shift);

	/* Construct iter->tags bit-mask from node->tags[tag] array */
	if (flags & RADIX_TREE_ITER_TAGGED) {
		unsigned tag_long, tag_bit;

		tag_long = offset / BITS_PER_LONG;
		tag_bit  = offset % BITS_PER_LONG;
		iter->tags = node->tags[tag][tag_long] >> tag_bit;
		/* This never happens if RADIX_TREE_TAG_LONGS == 1 */
		if (tag_long < RADIX_TREE_TAG_LONGS - 1) {
			/* Pick tags from next element */
			if (tag_bit)
				iter->tags |= node->tags[tag][tag_long + 1] <<
						(BITS_PER_LONG - tag_bit);
			/* Clip chunk size, here only BITS_PER_LONG tags */
			iter->next_index = index + BITS_PER_LONG;
		}
	}

	return node->slots + offset;
}
EXPORT_SYMBOL(radix_tree_next_chunk);

/**
 * radix_tree_range_tag_if_tagged - for each item in given range set given
 *				   tag if item has another tag set
 * @root:		radix tree root
 * @first_indexp:	pointer to a starting index of a range to scan
 * @last_index:		last index of a range to scan
 * @nr_to_tag:		maximum number items to tag
 * @iftag:		tag index to test
 * @settag:		tag index to set if tested tag is set
 *
 * This function scans range of radix tree from first_index to last_index
 * (inclusive).  For each item in the range if iftag is set, the function sets
 * also settag. The function stops either after tagging nr_to_tag items or
 * after reaching last_index.
 *
 * The tags must be set from the leaf level only and propagated back up the
 * path to the root. We must do this so that we resolve the full path before
 * setting any tags on intermediate nodes. If we set tags as we descend, then
 * we can get to the leaf node and find that the index that has the iftag
 * set is outside the range we are scanning. This reults in dangling tags and
 * can lead to problems with later tag operations (e.g. livelocks on lookups).
 *
 * The function returns the number of leaves where the tag was set and sets
 * *first_indexp to the first unscanned index.
 * WARNING! *first_indexp can wrap if last_index is ULONG_MAX. Caller must
 * be prepared to handle that.
 */
unsigned long radix_tree_range_tag_if_tagged(struct radix_tree_root *root,
		unsigned long *first_indexp, unsigned long last_index,
		unsigned long nr_to_tag,
		unsigned int iftag, unsigned int settag)
{
	struct radix_tree_node *parent, *node, *child;
	unsigned long maxindex;
	unsigned long tagged = 0;
	unsigned long index = *first_indexp;

	radix_tree_load_root(root, &child, &maxindex);
	last_index = min(last_index, maxindex);
	if (index > last_index)
		return 0;
	if (!nr_to_tag)
		return 0;
	if (!root_tag_get(root, iftag)) {
		*first_indexp = last_index + 1;
		return 0;
	}
	if (!radix_tree_is_internal_node(child)) {
		*first_indexp = last_index + 1;
		root_tag_set(root, settag);
		return 1;
	}

	node = entry_to_node(child);

	for (;;) {
		unsigned offset = radix_tree_descend(node, &child, index);
		if (!child)
			goto next;
		if (!tag_get(node, iftag, offset))
			goto next;
		/* Sibling slots never have tags set on them */
		if (radix_tree_is_internal_node(child)) {
			node = entry_to_node(child);
			continue;
		}

		/* tag the leaf */
		tagged++;
		tag_set(node, settag, offset);

		/* walk back up the path tagging interior nodes */
		parent = node;
		for (;;) {
			offset = parent->offset;
			parent = parent->parent;
			if (!parent)
				break;
			/* stop if we find a node with the tag already set */
			if (tag_get(parent, settag, offset))
				break;
			tag_set(parent, settag, offset);
		}
 next:
		/* Go to next entry in node */
		index = ((index >> node->shift) + 1) << node->shift;
		/* Overflow can happen when last_index is ~0UL... */
		if (index > last_index || !index)
			break;
		offset = (index >> node->shift) & RADIX_TREE_MAP_MASK;
		while (offset == 0) {
			/*
			 * We've fully scanned this node. Go up. Because
			 * last_index is guaranteed to be in the tree, what
			 * we do below cannot wander astray.
			 */
			node = node->parent;
			offset = (index >> node->shift) & RADIX_TREE_MAP_MASK;
		}
		if (is_sibling_entry(node, node->slots[offset]))
			goto next;
		if (tagged >= nr_to_tag)
			break;
	}
	/*
	 * We need not to tag the root tag if there is no tag which is set with
	 * settag within the range from *first_indexp to last_index.
	 */
	if (tagged > 0)
		root_tag_set(root, settag);
	*first_indexp = index;

	return tagged;
}
EXPORT_SYMBOL(radix_tree_range_tag_if_tagged);

/**
 *	radix_tree_gang_lookup - perform multiple lookup on a radix tree
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *
 *	Performs an index-ascending scan of the tree for present items.  Places
 *	them at *@results and returns the number of items which were placed at
 *	*@results.
 *
 *	The implementation is naive.
 *
 *	Like radix_tree_lookup, radix_tree_gang_lookup may be called under
 *	rcu_read_lock. In this case, rather than the returned results being
 *	an atomic snapshot of the tree at a single point in time, the
 *	semantics of an RCU protected gang lookup are as though multiple
 *	radix_tree_lookups have been issued in individual locks, and results
 *	stored in 'results'.
 */
unsigned int
radix_tree_gang_lookup(struct radix_tree_root *root, void **results,
			unsigned long first_index, unsigned int max_items)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!max_items))
		return 0;

	radix_tree_for_each_slot(slot, root, &iter, first_index) {
		results[ret] = rcu_dereference_raw(*slot);
		if (!results[ret])
			continue;
		if (radix_tree_is_internal_node(results[ret])) {
			slot = radix_tree_iter_retry(&iter);
			continue;
		}
		if (++ret == max_items)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup);

/**
 *	radix_tree_gang_lookup_slot - perform multiple slot lookup on radix tree
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@indices:	where their indices should be placed (but usually NULL)
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *
 *	Performs an index-ascending scan of the tree for present items.  Places
 *	their slots at *@results and returns the number of items which were
 *	placed at *@results.
 *
 *	The implementation is naive.
 *
 *	Like radix_tree_gang_lookup as far as RCU and locking goes. Slots must
 *	be dereferenced with radix_tree_deref_slot, and if using only RCU
 *	protection, radix_tree_deref_slot may fail requiring a retry.
 */
unsigned int
radix_tree_gang_lookup_slot(struct radix_tree_root *root,
			void ***results, unsigned long *indices,
			unsigned long first_index, unsigned int max_items)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!max_items))
		return 0;

	radix_tree_for_each_slot(slot, root, &iter, first_index) {
		results[ret] = slot;
		if (indices)
			indices[ret] = iter.index;
		if (++ret == max_items)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup_slot);

/**
 *	radix_tree_gang_lookup_tag - perform multiple lookup on a radix tree
 *	                             based on a tag
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *	@tag:		the tag index (< RADIX_TREE_MAX_TAGS)
 *
 *	Performs an index-ascending scan of the tree for present items which
 *	have the tag indexed by @tag set.  Places the items at *@results and
 *	returns the number of items which were placed at *@results.
 */
unsigned int
radix_tree_gang_lookup_tag(struct radix_tree_root *root, void **results,
		unsigned long first_index, unsigned int max_items,
		unsigned int tag)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!max_items))
		return 0;

	radix_tree_for_each_tagged(slot, root, &iter, first_index, tag) {
		results[ret] = rcu_dereference_raw(*slot);
		if (!results[ret])
			continue;
		if (radix_tree_is_internal_node(results[ret])) {
			slot = radix_tree_iter_retry(&iter);
			continue;
		}
		if (++ret == max_items)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup_tag);

/**
 *	radix_tree_gang_lookup_tag_slot - perform multiple slot lookup on a
 *					  radix tree based on a tag
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *	@tag:		the tag index (< RADIX_TREE_MAX_TAGS)
 *
 *	Performs an index-ascending scan of the tree for present items which
 *	have the tag indexed by @tag set.  Places the slots at *@results and
 *	returns the number of slots which were placed at *@results.
 */
unsigned int
radix_tree_gang_lookup_tag_slot(struct radix_tree_root *root, void ***results,
		unsigned long first_index, unsigned int max_items,
		unsigned int tag)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!max_items))
		return 0;

	radix_tree_for_each_tagged(slot, root, &iter, first_index, tag) {
		results[ret] = slot;
		if (++ret == max_items)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup_tag_slot);

#if defined(CONFIG_SHMEM) && defined(CONFIG_SWAP)
#include <linux/sched.h> /* for cond_resched() */

struct locate_info {
	unsigned long found_index;
	bool stop;
};

/*
 * This linear search is at present only useful to shmem_unuse_inode().
 */
static unsigned long __locate(struct radix_tree_node *slot, void *item,
			      unsigned long index, struct locate_info *info)
{
	unsigned long i;

	do {
		unsigned int shift = slot->shift;

		for (i = (index >> shift) & RADIX_TREE_MAP_MASK;
		     i < RADIX_TREE_MAP_SIZE;
		     i++, index += (1UL << shift)) {
			struct radix_tree_node *node =
					rcu_dereference_raw(slot->slots[i]);
			if (node == RADIX_TREE_RETRY)
				goto out;
			if (!radix_tree_is_internal_node(node)) {
				if (node == item) {
					info->found_index = index;
					info->stop = true;
					goto out;
				}
				continue;
			}
			node = entry_to_node(node);
			if (is_sibling_entry(slot, node))
				continue;
			slot = node;
			break;
		}
	} while (i < RADIX_TREE_MAP_SIZE);

out:
	if ((index == 0) && (i == RADIX_TREE_MAP_SIZE))
		info->stop = true;
	return index;
}

/**
 *	radix_tree_locate_item - search through radix tree for item
 *	@root:		radix tree root
 *	@item:		item to be found
 *
 *	Returns index where item was found, or -1 if not found.
 *	Caller must hold no lock (since this time-consuming function needs
 *	to be preemptible), and must check afterwards if item is still there.
 */
unsigned long radix_tree_locate_item(struct radix_tree_root *root, void *item)
{
	struct radix_tree_node *node;
	unsigned long max_index;
	unsigned long cur_index = 0;
	struct locate_info info = {
		.found_index = -1,
		.stop = false,
	};

	do {
		rcu_read_lock();
		node = rcu_dereference_raw(root->rnode);
		if (!radix_tree_is_internal_node(node)) {
			rcu_read_unlock();
			if (node == item)
				info.found_index = 0;
			break;
		}

		node = entry_to_node(node);

		max_index = node_maxindex(node);
		if (cur_index > max_index) {
			rcu_read_unlock();
			break;
		}

		cur_index = __locate(node, item, cur_index, &info);
		rcu_read_unlock();
		cond_resched();
	} while (!info.stop && cur_index <= max_index);

	return info.found_index;
}
#else
unsigned long radix_tree_locate_item(struct radix_tree_root *root, void *item)
{
	return -1;
}
#endif /* CONFIG_SHMEM && CONFIG_SWAP */

/**
 *	radix_tree_shrink    -    shrink radix tree to minimum height
 *	@root		radix tree root
 */
static inline bool radix_tree_shrink(struct radix_tree_root *root)
{
	bool shrunk = false;

	for (;;) {
		struct radix_tree_node *node = root->rnode;
		struct radix_tree_node *child;

		if (!radix_tree_is_internal_node(node))
			break;
		node = entry_to_node(node);

		/*
		 * The candidate node has more than one child, or its child
		 * is not at the leftmost slot, or the child is a multiorder
		 * entry, we cannot shrink.
		 */
		if (node->count != 1)
			break;
		child = node->slots[0];
		if (!child)
			break;
		if (!radix_tree_is_internal_node(child) && node->shift)
			break;

		if (radix_tree_is_internal_node(child))
			entry_to_node(child)->parent = NULL;

		/*
		 * We don't need rcu_assign_pointer(), since we are simply
		 * moving the node from one part of the tree to another: if it
		 * was safe to dereference the old pointer to it
		 * (node->slots[0]), it will be safe to dereference the new
		 * one (root->rnode) as far as dependent read barriers go.
		 */
		root->rnode = child;

		/*
		 * We have a dilemma here. The node's slot[0] must not be
		 * NULLed in case there are concurrent lookups expecting to
		 * find the item. However if this was a bottom-level node,
		 * then it may be subject to the slot pointer being visible
		 * to callers dereferencing it. If item corresponding to
		 * slot[0] is subsequently deleted, these callers would expect
		 * their slot to become empty sooner or later.
		 *
		 * For example, lockless pagecache will look up a slot, deref
		 * the page pointer, and if the page has 0 refcount it means it
		 * was concurrently deleted from pagecache so try the deref
		 * again. Fortunately there is already a requirement for logic
		 * to retry the entire slot lookup -- the indirect pointer
		 * problem (replacing direct root node with an indirect pointer
		 * also results in a stale slot). So tag the slot as indirect
		 * to force callers to retry.
		 */
		if (!radix_tree_is_internal_node(child))
			node->slots[0] = RADIX_TREE_RETRY;

		radix_tree_node_free(node);
		shrunk = true;
	}

	return shrunk;
}

/**
 *	__radix_tree_delete_node    -    try to free node after clearing a slot
 *	@root:		radix tree root
 *	@node:		node containing @index
 *
 *	After clearing the slot at @index in @node from radix tree
 *	rooted at @root, call this function to attempt freeing the
 *	node and shrinking the tree.
 *
 *	Returns %true if @node was freed, %false otherwise.
 */
bool __radix_tree_delete_node(struct radix_tree_root *root,
			      struct radix_tree_node *node)
{
	bool deleted = false;

	do {
		struct radix_tree_node *parent;

		if (node->count) {
			if (node == entry_to_node(root->rnode))
				deleted |= radix_tree_shrink(root);
			return deleted;
		}

		parent = node->parent;
		if (parent) {
			parent->slots[node->offset] = NULL;
			parent->count--;
		} else {
			root_tag_clear_all(root);
			root->rnode = NULL;
		}

		radix_tree_node_free(node);
		deleted = true;

		node = parent;
	} while (node);

	return deleted;
}

static inline void delete_sibling_entries(struct radix_tree_node *node,
					void *ptr, unsigned offset)
{
#ifdef CONFIG_RADIX_TREE_MULTIORDER
	int i;
	for (i = 1; offset + i < RADIX_TREE_MAP_SIZE; i++) {
		if (node->slots[offset + i] != ptr)
			break;
		node->slots[offset + i] = NULL;
		node->count--;
	}
#endif
}

/**
 *	radix_tree_delete_item    -    delete an item from a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *	@item:		expected item
 *
 *	Remove @item at @index from the radix tree rooted at @root.
 *
 *	Returns the address of the deleted item, or NULL if it was not present
 *	or the entry at the given @index was not @item.
 */
void *radix_tree_delete_item(struct radix_tree_root *root,
			     unsigned long index, void *item)
{
	struct radix_tree_node *node;
	unsigned int offset;
	void **slot;
	void *entry;
	int tag;

	entry = __radix_tree_lookup(root, index, &node, &slot);
	if (!entry)
		return NULL;

	if (item && entry != item)
		return NULL;

	if (!node) {
		root_tag_clear_all(root);
		root->rnode = NULL;
		return entry;
	}

	offset = get_slot_offset(node, slot);

	/* Clear all tags associated with the item to be deleted.  */
	for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++)
		node_tag_clear(root, node, tag, offset);

	delete_sibling_entries(node, node_to_entry(slot), offset);
	node->slots[offset] = NULL;
	node->count--;

	__radix_tree_delete_node(root, node);

	return entry;
}
EXPORT_SYMBOL(radix_tree_delete_item);

/**
 *	radix_tree_delete    -    delete an item from a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *
 *	Remove the item at @index from the radix tree rooted at @root.
 *
 *	Returns the address of the deleted item, or NULL if it was not present.
 */
void *radix_tree_delete(struct radix_tree_root *root, unsigned long index)
{
	return radix_tree_delete_item(root, index, NULL);
}
EXPORT_SYMBOL(radix_tree_delete);

void radix_tree_clear_tags(struct radix_tree_root *root,
			   struct radix_tree_node *node,
			   void **slot)
{
	if (node) {
		unsigned int tag, offset = get_slot_offset(node, slot);
		for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++)
			node_tag_clear(root, node, tag, offset);
	} else {
		/* Clear root node tags */
		root->gfp_mask &= __GFP_BITS_MASK;
	}
}

/**
 *	radix_tree_tagged - test whether any items in the tree are tagged
 *	@root:		radix tree root
 *	@tag:		tag to test
 */
int radix_tree_tagged(struct radix_tree_root *root, unsigned int tag)
{
	return root_tag_get(root, tag);
}
EXPORT_SYMBOL(radix_tree_tagged);

static void
radix_tree_node_ctor(void *arg)
{
	struct radix_tree_node *node = arg;

	memset(node, 0, sizeof(*node));
	INIT_LIST_HEAD(&node->private_list);
}

static __init unsigned long __maxindex(unsigned int height)
{
	unsigned int width = height * RADIX_TREE_MAP_SHIFT;
	int shift = RADIX_TREE_INDEX_BITS - width;

	if (shift < 0)
		return ~0UL;
	if (shift >= BITS_PER_LONG)
		return 0UL;
	return ~0UL >> shift;
}

static __init void radix_tree_init_maxnodes(void)
{
	unsigned long height_to_maxindex[RADIX_TREE_MAX_PATH + 1];
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(height_to_maxindex); i++)
		height_to_maxindex[i] = __maxindex(i);
	for (i = 0; i < ARRAY_SIZE(height_to_maxnodes); i++) {
		for (j = i; j > 0; j--)
			height_to_maxnodes[i] += height_to_maxindex[j - 1] + 1;
	}
}

static int radix_tree_callback(struct notifier_block *nfb,
				unsigned long action, void *hcpu)
{
	int cpu = (long)hcpu;
	struct radix_tree_preload *rtp;
	struct radix_tree_node *node;

	/* Free per-cpu pool of preloaded nodes */
	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		rtp = &per_cpu(radix_tree_preloads, cpu);
		while (rtp->nr) {
			node = rtp->nodes;
			rtp->nodes = node->private_data;
			kmem_cache_free(radix_tree_node_cachep, node);
			rtp->nr--;
		}
	}
	return NOTIFY_OK;
}

void __init radix_tree_init(void)
{
	radix_tree_node_cachep = kmem_cache_create("radix_tree_node",
			sizeof(struct radix_tree_node), 0,
			SLAB_PANIC | SLAB_RECLAIM_ACCOUNT,
			radix_tree_node_ctor);
	radix_tree_init_maxnodes();
	hotcpu_notifier(radix_tree_callback, 0);
}
