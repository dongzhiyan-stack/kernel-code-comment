/*
 * Copyright (c) 2003-2006, Cluster File Systems, Inc, info@clusterfs.com
 * Written by Alex Tomas <alex@clusterfs.com>
 *
 * Architecture independence:
 *   Copyright (c) 2005, Bull S.A.
 *   Written by Pierre Peiffer <pierre.peiffer@bull.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 */

/*
 * Extents support for EXT4
 *
 * TODO:
 *   - ext4*_error() should be used in some situations
 *   - analyze all BUG()/BUG_ON(), use -EIO where appropriate
 *   - smart tree reduction
 */

#include <linux/fs.h>
#include <linux/time.h>
#include <linux/jbd2.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/falloc.h>
#include <asm/uaccess.h>
#include <linux/fiemap.h>
#include "ext4_jbd2.h"
#include "ext4_extents.h"
#include "xattr.h"

#include <trace/events/ext4.h>

/*
 * used by extent splitting.
 */
//zeroout看着一般用不到，像是如果把ext4_extent因内存不足分割失败后恢复之用
#define EXT4_EXT_MAY_ZEROOUT	0x1  /* safe to zeroout if split fails \
					due to ENOSPC */
#define EXT4_EXT_MARK_UNINIT1	0x2  /* mark first half uninitialized *///标记分割后的第1段未初始化状态
#define EXT4_EXT_MARK_UNINIT2	0x4  /* mark second half uninitialized *///标记分割后的第2段未初始化状态

#define EXT4_EXT_DATA_VALID1	0x8  /* first half contains valid data */
#define EXT4_EXT_DATA_VALID2	0x10 /* second half contains valid data */

static __le32 ext4_extent_block_csum(struct inode *inode,
				     struct ext4_extent_header *eh)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	__u32 csum;

	csum = ext4_chksum(sbi, ei->i_csum_seed, (__u8 *)eh,
			   EXT4_EXTENT_TAIL_OFFSET(eh));
	return cpu_to_le32(csum);
}

static int ext4_extent_block_csum_verify(struct inode *inode,
					 struct ext4_extent_header *eh)
{
	struct ext4_extent_tail *et;

	if (!EXT4_HAS_RO_COMPAT_FEATURE(inode->i_sb,
		EXT4_FEATURE_RO_COMPAT_METADATA_CSUM))
		return 1;

	et = find_ext4_extent_tail(eh);
	if (et->et_checksum != ext4_extent_block_csum(inode, eh))
		return 0;
	return 1;
}

static void ext4_extent_block_csum_set(struct inode *inode,
				       struct ext4_extent_header *eh)
{
	struct ext4_extent_tail *et;

	if (!EXT4_HAS_RO_COMPAT_FEATURE(inode->i_sb,
		EXT4_FEATURE_RO_COMPAT_METADATA_CSUM))
		return;

	et = find_ext4_extent_tail(eh);
	et->et_checksum = ext4_extent_block_csum(inode, eh);
}

static int ext4_split_extent(handle_t *handle,
				struct inode *inode,
				struct ext4_ext_path *path,
				struct ext4_map_blocks *map,
				int split_flag,
				int flags);

static int ext4_split_extent_at(handle_t *handle,
			     struct inode *inode,
			     struct ext4_ext_path *path,
			     ext4_lblk_t split,
			     int split_flag,
			     int flags);

static int ext4_find_delayed_extent(struct inode *inode,
				    struct extent_status *newes);

static int ext4_ext_truncate_extend_restart(handle_t *handle,
					    struct inode *inode,
					    int needed)
{
	int err;

	if (!ext4_handle_valid(handle))
		return 0;
	if (handle->h_buffer_credits > needed)
		return 0;
	err = ext4_journal_extend(handle, needed);
	if (err <= 0)
		return err;
	err = ext4_truncate_restart_trans(handle, inode, needed);
	if (err == 0)
		err = -EAGAIN;

	return err;
}

/*
 * could return:
 *  - EROFS
 *  - ENOMEM
 */
static int ext4_ext_get_access(handle_t *handle, struct inode *inode,
				struct ext4_ext_path *path)
{
	if (path->p_bh) {
		/* path points to block */
		return ext4_journal_get_write_access(handle, path->p_bh);
	}
	/* path points to leaf/index in inode body */
	/* we use in-core data, no need to protect them */
	return 0;
}

/*
 * could return:
 *  - EROFS
 *  - ENOMEM
 *  - EIO
 */
//ext4_extent映射的逻辑块范围可能发生变化了，标记对应的物理块映射的bh或者文件inode脏.
//为什么ext4_extent变化会影响到物理块映射的bh或者文件inode脏呢?
int __ext4_ext_dirty(const char *where, unsigned int line, handle_t *handle,
		     struct inode *inode, struct ext4_ext_path *path)
{
	int err;
	if (path->p_bh) {
		ext4_extent_block_csum_set(inode, ext_block_hdr(path->p_bh));
		/* path points to block */
		err = __ext4_handle_dirty_metadata(where, line, handle,
						   inode, path->p_bh);
	} else {
		/* path points to leaf/index in inode body */
		err = ext4_mark_inode_dirty(handle, inode);
	}
	return err;
}
//找到map->m_lblk或者ex->ee_block映射的物理块地址并返回
static ext4_fsblk_t ext4_ext_find_goal(struct inode *inode,
			      struct ext4_ext_path *path,
			      ext4_lblk_t block)//block是map->m_lblk或者ex->ee_block
{
	if (path) {
		int depth = path->p_depth;
		struct ext4_extent *ex;

		/*
		 * Try to predict block placement assuming that we are
		 * filling in a file which will eventually be
		 * non-sparse --- i.e., in the case of libbfd writing
		 * an ELF object sections out-of-order but in a way
		 * the eventually results in a contiguous object or
		 * executable file, or some database extending a table
		 * space file.  However, this is actually somewhat
		 * non-ideal if we are writing a sparse file such as
		 * qemu or KVM writing a raw image file that is going
		 * to stay fairly sparse, since it will end up
		 * fragmenting the file system's free space.  Maybe we
		 * should have some hueristics or some way to allow
		 * userspace to pass a hint to file system,
		 * especially if the latter case turns out to be
		 * common.
		 */
		ex = path[depth].p_ext;
		if (ex) {
            //ex的起始物理块地址
			ext4_fsblk_t ext_pblk = ext4_ext_pblock(ex);
            //ex的起始逻辑块地址
			ext4_lblk_t ext_block = le32_to_cpu(ex->ee_block);

            //block映射的物理块地址=ex的起始物理块地址 + (ex的起始逻辑块地址与block的差值)
			if (block > ext_block)
				return ext_pblk + (block - ext_block);
			else
				return ext_pblk - (ext_block - block);
		}

		/* it looks like index is empty;
		 * try to find starting block from index itself */
		//???????????????????
		if (path[depth].p_bh)
			return path[depth].p_bh->b_blocknr;
	}

	/* OK. use inode's group */
    //从inode group分配一个物理块
	return ext4_inode_to_goal_block(inode);
}

/*
 * Allocation for a meta data block
 */
//从ext4文件系统元数据区分配一个物理块，返回它的物理块号。应该是4K大小，保存ext4 extent B+树索引节点或者叶子结点的N个ext4_extent_idx、ext4_extent结构
static ext4_fsblk_t
ext4_ext_new_meta_block(handle_t *handle, struct inode *inode,
			struct ext4_ext_path *path,
			struct ext4_extent *ex, int *err, unsigned int flags)
{
	ext4_fsblk_t goal, newblock;
    //找到ex->ee_block映射的物理块地址并返回给goal，这只是个参考的目标物理块号
	goal = ext4_ext_find_goal(inode, path, le32_to_cpu(ex->ee_block));
    //以goal作为目标物理块地址，真正的从ext4 文件系统分配一个物理块，物理块的地址是newblock，newblock和goal都是磁盘物理块号，
    //二者有时相等，有时不相等。
	newblock = ext4_new_meta_blocks(handle, inode, goal, flags,
					NULL, err);
	return newblock;
}

static inline int ext4_ext_space_block(struct inode *inode, int check)
{
	int size;
    //这是计算一个4K大小的物理块块能容纳多少个ext4_extent结构，当然还要加上ext4 extent B+树叶子节点头ext4_extent_header
	size = (inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 6)
		size = 6;
#endif
	return size;
}

static inline int ext4_ext_space_block_idx(struct inode *inode, int check)
{
	int size;
    //这是计算一个4K大小的物理块块能容纳多少个ext4_extent_idx结构，当然还要加上ext4 extent B+树索引节点头ext4_extent_header
	size = (inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 5)
		size = 5;
#endif
	return size;
}

static inline int ext4_ext_space_root(struct inode *inode, int check)
{
	int size;

	size = sizeof(EXT4_I(inode)->i_data);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 3)
		size = 3;
#endif
	return size;
}

static inline int ext4_ext_space_root_idx(struct inode *inode, int check)
{
	int size;

	size = sizeof(EXT4_I(inode)->i_data);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 4)
		size = 4;
#endif
	return size;
}

/*
 * Calculate the number of metadata blocks needed
 * to allocate @blocks
 * Worse case is one block per extent
 */
int ext4_ext_calc_metadata_amount(struct inode *inode, ext4_lblk_t lblock)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	int idxs;

	idxs = ((inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
		/ sizeof(struct ext4_extent_idx));

	/*
	 * If the new delayed allocation block is contiguous with the
	 * previous da block, it can share index blocks with the
	 * previous block, so we only need to allocate a new index
	 * block every idxs leaf blocks.  At ldxs**2 blocks, we need
	 * an additional index block, and at ldxs**3 blocks, yet
	 * another index blocks.
	 */
	if (ei->i_da_metadata_calc_len &&
	    ei->i_da_metadata_calc_last_lblock+1 == lblock) {
		int num = 0;

		if ((ei->i_da_metadata_calc_len % idxs) == 0)
			num++;
		if ((ei->i_da_metadata_calc_len % (idxs*idxs)) == 0)
			num++;
		if ((ei->i_da_metadata_calc_len % (idxs*idxs*idxs)) == 0) {
			num++;
			ei->i_da_metadata_calc_len = 0;
		} else
			ei->i_da_metadata_calc_len++;
		ei->i_da_metadata_calc_last_lblock++;
		return num;
	}

	/*
	 * In the worst case we need a new set of index blocks at
	 * every level of the inode's extent tree.
	 */
	ei->i_da_metadata_calc_len = 1;
	ei->i_da_metadata_calc_last_lblock = lblock;
	return ext_depth(inode) + 1;
}

static int
ext4_ext_max_entries(struct inode *inode, int depth)
{
	int max;

	if (depth == ext_depth(inode)) {
		if (depth == 0)
			max = ext4_ext_space_root(inode, 1);
		else
			max = ext4_ext_space_root_idx(inode, 1);
	} else {
		if (depth == 0)
			max = ext4_ext_space_block(inode, 1);
		else
			max = ext4_ext_space_block_idx(inode, 1);
	}

	return max;
}

static int ext4_valid_extent(struct inode *inode, struct ext4_extent *ext)
{
	ext4_fsblk_t block = ext4_ext_pblock(ext);
	int len = ext4_ext_get_actual_len(ext);
	ext4_lblk_t lblock = le32_to_cpu(ext->ee_block);
	ext4_lblk_t last = lblock + len - 1;

	if (len == 0 || lblock > last)
		return 0;
	return ext4_data_block_valid(EXT4_SB(inode->i_sb), block, len);
}

static int ext4_valid_extent_idx(struct inode *inode,
				struct ext4_extent_idx *ext_idx)
{
	ext4_fsblk_t block = ext4_idx_pblock(ext_idx);

	return ext4_data_block_valid(EXT4_SB(inode->i_sb), block, 1);
}

static int ext4_valid_extent_entries(struct inode *inode,
				struct ext4_extent_header *eh,
				int depth)
{
	unsigned short entries;
	if (eh->eh_entries == 0)
		return 1;

	entries = le16_to_cpu(eh->eh_entries);

	if (depth == 0) {
		/* leaf entries */
		struct ext4_extent *ext = EXT_FIRST_EXTENT(eh);
		struct ext4_super_block *es = EXT4_SB(inode->i_sb)->s_es;
		ext4_fsblk_t pblock = 0;
		ext4_lblk_t lblock = 0;
		ext4_lblk_t prev = 0;
		int len = 0;
		while (entries) {
			if (!ext4_valid_extent(inode, ext))
				return 0;

			/* Check for overlapping extents */
			lblock = le32_to_cpu(ext->ee_block);
			len = ext4_ext_get_actual_len(ext);
			if ((lblock <= prev) && prev) {
				pblock = ext4_ext_pblock(ext);
				es->s_last_error_block = cpu_to_le64(pblock);
				return 0;
			}
			ext++;
			entries--;
			prev = lblock + len - 1;
		}
	} else {
		struct ext4_extent_idx *ext_idx = EXT_FIRST_INDEX(eh);
		while (entries) {
			if (!ext4_valid_extent_idx(inode, ext_idx))
				return 0;
			ext_idx++;
			entries--;
		}
	}
	return 1;
}

static int __ext4_ext_check(const char *function, unsigned int line,
			    struct inode *inode, struct ext4_extent_header *eh,
			    int depth)
{
	const char *error_msg;
	int max = 0;

	if (unlikely(eh->eh_magic != EXT4_EXT_MAGIC)) {
		error_msg = "invalid magic";
		goto corrupted;
	}
	if (unlikely(le16_to_cpu(eh->eh_depth) != depth)) {
		error_msg = "unexpected eh_depth";
		goto corrupted;
	}
	if (unlikely(eh->eh_max == 0)) {
		error_msg = "invalid eh_max";
		goto corrupted;
	}
	max = ext4_ext_max_entries(inode, depth);
	if (unlikely(le16_to_cpu(eh->eh_max) > max)) {
		error_msg = "too large eh_max";
		goto corrupted;
	}
	if (unlikely(le16_to_cpu(eh->eh_entries) > le16_to_cpu(eh->eh_max))) {
		error_msg = "invalid eh_entries";
		goto corrupted;
	}
	if (!ext4_valid_extent_entries(inode, eh, depth)) {
		error_msg = "invalid extent entries";
		goto corrupted;
	}
	/* Verify checksum on non-root extent tree nodes */
	if (ext_depth(inode) != depth &&
	    !ext4_extent_block_csum_verify(inode, eh)) {
		error_msg = "extent tree corrupted";
		goto corrupted;
	}
	return 0;

corrupted:
	ext4_error_inode(inode, function, line, 0,
			"bad header/extent: %s - magic %x, "
			"entries %u, max %u(%u), depth %u(%u)",
			error_msg, le16_to_cpu(eh->eh_magic),
			le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max),
			max, le16_to_cpu(eh->eh_depth), depth);

	return -EIO;
}

#define ext4_ext_check(inode, eh, depth)	\
	__ext4_ext_check(__func__, __LINE__, inode, eh, depth)

int ext4_ext_check_inode(struct inode *inode)
{
	return ext4_ext_check(inode, ext_inode_hdr(inode), ext_depth(inode));
}

static int __ext4_ext_check_block(const char *function, unsigned int line,
				  struct inode *inode,
				  struct ext4_extent_header *eh,
				  int depth,
				  struct buffer_head *bh)
{
	int ret;

	if (buffer_verified(bh))
		return 0;
	ret = ext4_ext_check(inode, eh, depth);
	if (ret)
		return ret;
	set_buffer_verified(bh);
	return ret;
}

#define ext4_ext_check_block(inode, eh, depth, bh)	\
	__ext4_ext_check_block(__func__, __LINE__, inode, eh, depth, bh)

#ifdef EXT_DEBUG
static void ext4_ext_show_path(struct inode *inode, struct ext4_ext_path *path)
{
	int k, l = path->p_depth;

	ext_debug("path:");
	for (k = 0; k <= l; k++, path++) {
		if (path->p_idx) {
		  ext_debug("  %d->%llu", le32_to_cpu(path->p_idx->ei_block),
			    ext4_idx_pblock(path->p_idx));
		} else if (path->p_ext) {
			ext_debug("  %d:[%d]%d:%llu ",
				  le32_to_cpu(path->p_ext->ee_block),
				  ext4_ext_is_uninitialized(path->p_ext),
				  ext4_ext_get_actual_len(path->p_ext),
				  ext4_ext_pblock(path->p_ext));
		} else
			ext_debug("  []");
	}
	ext_debug("\n");
}

static void ext4_ext_show_leaf(struct inode *inode, struct ext4_ext_path *path)
{
	int depth = ext_depth(inode);
	struct ext4_extent_header *eh;
	struct ext4_extent *ex;
	int i;

	if (!path)
		return;

	eh = path[depth].p_hdr;
	ex = EXT_FIRST_EXTENT(eh);

	ext_debug("Displaying leaf extents for inode %lu\n", inode->i_ino);

	for (i = 0; i < le16_to_cpu(eh->eh_entries); i++, ex++) {
		ext_debug("%d:[%d]%d:%llu ", le32_to_cpu(ex->ee_block),
			  ext4_ext_is_uninitialized(ex),
			  ext4_ext_get_actual_len(ex), ext4_ext_pblock(ex));
	}
	ext_debug("\n");
}

static void ext4_ext_show_move(struct inode *inode, struct ext4_ext_path *path,
			ext4_fsblk_t newblock, int level)
{
	int depth = ext_depth(inode);
	struct ext4_extent *ex;

	if (depth != level) {
		struct ext4_extent_idx *idx;
		idx = path[level].p_idx;
		while (idx <= EXT_MAX_INDEX(path[level].p_hdr)) {
			ext_debug("%d: move %d:%llu in new index %llu\n", level,
					le32_to_cpu(idx->ei_block),
					ext4_idx_pblock(idx),
					newblock);
			idx++;
		}

		return;
	}

	ex = path[depth].p_ext;
	while (ex <= EXT_MAX_EXTENT(path[depth].p_hdr)) {
		ext_debug("move %d:%llu:[%d]%d in new leaf %llu\n",
				le32_to_cpu(ex->ee_block),
				ext4_ext_pblock(ex),
				ext4_ext_is_uninitialized(ex),
				ext4_ext_get_actual_len(ex),
				newblock);
		ex++;
	}
}

#else
#define ext4_ext_show_path(inode, path)
#define ext4_ext_show_leaf(inode, path)
#define ext4_ext_show_move(inode, path, newblock, level)
#endif

void ext4_ext_drop_refs(struct ext4_ext_path *path)
{
	int depth = path->p_depth;
	int i;

	for (i = 0; i <= depth; i++, path++)
		if (path->p_bh) {
			brelse(path->p_bh);
			path->p_bh = NULL;
		}
}

/*
 * ext4_ext_binsearch_idx:
 * binary search for the closest index of the given block
 * the header must be checked before calling this
 */
//利用二分法在ext4 extent B+树path->p_hdr[]后边的ext4_extent_idx[]数组中，找到起始逻辑块
//地址最接近传入的起始逻辑块地址block的ext4_extent_idx。path->p_idx指向这个ext4_extent_idx
static void
ext4_ext_binsearch_idx(struct inode *inode,
			struct ext4_ext_path *path, ext4_lblk_t block)
{//block是传入的起始逻辑块地址
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent_idx *r, *l, *m;


	ext_debug("binsearch for %u(idx):  ", block);
    /*如果索引节点只有一个ext4_extent_idx结构，这样下边while不成立，path->p_idx就指向第一个索引节点。特别注意，ext4_ext_binsearch_idx()
    找到的ext4_extent_idx的起始逻辑块地址<=block*/
    
	l = EXT_FIRST_INDEX(eh) + 1;//l指向ext4_extent_header后边的ext4_extent_idx数组的第2个ext4_extent_idx成员
	r = EXT_LAST_INDEX(eh);//r指向ext4_extent_header后边的ext4_extent_idx数组的最后一个ext4_extent_idx成员

    //在l和r指向的ext4_extent_idx数组之间，找到一个ext4_extent_idx->ei_block最接近
    //传入的起始逻辑块地址block的。ext4_extent_idx是extent B+数索引节点，其成员ei_block是
    //这个索引节点的起始逻辑块地址。注意，这个ext4_extent_idx->ei_block <= 传入的
    //起始逻辑块地址block，并且ext4_extent_idx->ei_block最接近传入的起始逻辑块地址block
    while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ei_block))
			r = m - 1;
		else
			l = m + 1;
		ext_debug("%p(%u):%p(%u):%p(%u) ", l, le32_to_cpu(l->ei_block),
				m, le32_to_cpu(m->ei_block),
				r, le32_to_cpu(r->ei_block));
	}
    //path->p_idx指向起始逻辑块地址最接近传入的起始逻辑块地址block的ext4_extent_idx
	path->p_idx = l - 1;
	ext_debug("  -> %u->%lld ", le32_to_cpu(path->p_idx->ei_block),
		  ext4_idx_pblock(path->p_idx));

#ifdef CHECK_BINSEARCH
	{
		struct ext4_extent_idx *chix, *ix;
		int k;

		chix = ix = EXT_FIRST_INDEX(eh);
		for (k = 0; k < le16_to_cpu(eh->eh_entries); k++, ix++) {
		  if (k != 0 &&
		      le32_to_cpu(ix->ei_block) <= le32_to_cpu(ix[-1].ei_block)) {
				printk(KERN_DEBUG "k=%d, ix=0x%p, "
				       "first=0x%p\n", k,
				       ix, EXT_FIRST_INDEX(eh));
				printk(KERN_DEBUG "%u <= %u\n",
				       le32_to_cpu(ix->ei_block),
				       le32_to_cpu(ix[-1].ei_block));
			}
			BUG_ON(k && le32_to_cpu(ix->ei_block)
					   <= le32_to_cpu(ix[-1].ei_block));
			if (block < le32_to_cpu(ix->ei_block))
				break;
			chix = ix;
		}
		BUG_ON(chix != path->p_idx);
	}
#endif

}

/*
 * ext4_ext_binsearch:
 * binary search for closest extent of the given block
 * the header must be checked before calling this
 */
//利用二分法在ext4 extent B+树path->p_hdr[]后边的ext4_extent[]数组中，找到起始逻辑块地址
//最接近传入的起始逻辑块地址block的ext4_extent。path->p_ext指向这个ext4_extent
static void
ext4_ext_binsearch(struct inode *inode,
		struct ext4_ext_path *path, ext4_lblk_t block)
{//block是传入的起始逻辑块地址
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent *r, *l, *m;

    /*如果叶子结点没有一个ext4_extent结构，直接return*/
	if (eh->eh_entries == 0) {
		/*
		 * this leaf is empty:
		 * we get such a leaf in split/add case
		 */
		return;
	}
    /*如果叶子节点只有一个ext4_extent结构，这样下边while不成立，path->p_idx就指向第一个索引节点。特别注意，ext4_ext_binsearch()
    找到的ext4_extent的起始逻辑块地址<=block*/

	ext_debug("binsearch for %u:  ", block);

    //l指向ext4_extent_header后边的ext4_extent数组的第2个ext4_extent成员
	l = EXT_FIRST_EXTENT(eh) + 1;
    //r指向ext4_extent_header后边的ext4_extent数组的最后一个ext4_extent成员
	r = EXT_LAST_EXTENT(eh);

    //在l和r指向的ext4_extent数组之间，找到一个ext4_extent->ee_block最接近
    //传入的起始逻辑块地址block的。ext4_extent是extent B+数叶子节点，其成员ee_block是
    //这个叶子节点的起始逻辑块地址。注意，这个ext4_extent->ee_block <= 传入的
    //起始逻辑块地址block，并且ext4_extent->ei_block最接近传入的起始逻辑块地址block
	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ee_block))
			r = m - 1;
		else
			l = m + 1;
		ext_debug("%p(%u):%p(%u):%p(%u) ", l, le32_to_cpu(l->ee_block),
				m, le32_to_cpu(m->ee_block),
				r, le32_to_cpu(r->ee_block));
	}
    //path->p_ext指向起始逻辑块地址最接近传入的起始逻辑块地址block的ext4_extent
	path->p_ext = l - 1;
	ext_debug("  -> %d:%llu:[%d]%d ",
			le32_to_cpu(path->p_ext->ee_block),
			ext4_ext_pblock(path->p_ext),
			ext4_ext_is_uninitialized(path->p_ext),
			ext4_ext_get_actual_len(path->p_ext));

#ifdef CHECK_BINSEARCH
	{
		struct ext4_extent *chex, *ex;
		int k;

		chex = ex = EXT_FIRST_EXTENT(eh);
		for (k = 0; k < le16_to_cpu(eh->eh_entries); k++, ex++) {
			BUG_ON(k && le32_to_cpu(ex->ee_block)
					  <= le32_to_cpu(ex[-1].ee_block));
			if (block < le32_to_cpu(ex->ee_block))
				break;
			chex = ex;
		}
		BUG_ON(chex != path->p_ext);
	}
#endif

}

int ext4_ext_tree_init(handle_t *handle, struct inode *inode)
{
	struct ext4_extent_header *eh;

	eh = ext_inode_hdr(inode);
	eh->eh_depth = 0;
	eh->eh_entries = 0;
	eh->eh_magic = EXT4_EXT_MAGIC;
	eh->eh_max = cpu_to_le16(ext4_ext_space_root(inode, 0));
	ext4_mark_inode_dirty(handle, inode);
	return 0;
}
/*根据ext4 extent B+树的根节点的ext4_extent_header，先找到每一层索引节点中起始逻辑块地址最接近传入的逻辑块地址block的ext4_extent_idx
保存到path[ppos]->p_idx.然后找到最后一层的叶子节点中起始逻辑块地址最接近传入的逻辑块地址block的ext4_extent，保存到path[ppos]->p_ext，
这个ext4_extent才包含了逻辑块地址和物理块地址的映射关系。注意，找到这些起始逻辑块地址接近block的ext4_extent_idx和ext4_extent的
起始逻辑块地址<=block，在block的左边，必须这样。将来把block对应的ext4_extent插入ext4 extent B+树时，也是插入到这些ext4_extent_idx
和ext4_extent结构的右边。ext4 extent B+树索引节点和叶子节点中的ext4_extent_idx和ext4_extent的逻辑块地址从左到右依次增大，顺序排布。

说明可能出现一种特种情况，就是叶子节点中没有一个ext4_extent结构，则path[ppos].p_ext是NULL，但path[ppos].p_hdr指向这个叶子节点的头结点
*/
struct ext4_ext_path *
ext4_ext_find_extent(struct inode *inode, ext4_lblk_t block,
					struct ext4_ext_path *path)//block是传入的起始逻辑块地址
{
	struct ext4_extent_header *eh;
	struct buffer_head *bh;
	short int depth, i, ppos = 0, alloc = 0;
	int ret;
    //从ext4_inode_info->i_data数组得到ext4 extent B+树的根节点
	eh = ext_inode_hdr(inode);
    //xt4 extent B+树深度
	depth = ext_depth(inode);

	/* account possible depth increase */
	if (!path) {
        //按照B+树的深度分配ext4_ext_path结构
		path = kzalloc(sizeof(struct ext4_ext_path) * (depth + 2),
				GFP_NOFS);
		if (!path)
			return ERR_PTR(-ENOMEM);
		alloc = 1;
	}
	path[0].p_hdr = eh;
	path[0].p_bh = NULL;

	i = depth;

    /*ext4 extent B+树由索引节点和叶子节点组成
索引节点    ext4_extent_header + ext4_extent_idx +  ext4_extent_idx + ........
                                     |
索引节点               ext4_extent_header + ext4_extent_idx + ext4_extent_idx+ ........
                                               |
叶子节点                                    ext4_extent_header + ext4_extent + ext4_extent+ ........

    path[0].p_hdr指向B+树的根节点的ext4_extent_header。
    下边这个while循环是根据这个B+树的根节点的ext4_extent_header，先找到每一层
    索引节点中最接近传入的起始逻辑块地址block的ext4_extent_idx保存到path[ppos]->p_idx，
    然后找到最后一层的叶子节点中最接近传入的起始逻辑块地址block的ext4_extent，保存到
    path[ppos]->p_ext。这个ext4_extent才包含了逻辑块地址和物理块地址的映射关系。
    */
	/* walk through the tree */
	while (i) {
		ext_debug("depth %d: num %d, max %d\n",
			  ppos, le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));
        
        //利用二分法在ext4 extent B+树path[ppos]->p_hdr[]后边的ext4_extent_idx[]数组中，
        //找到起始逻辑块地址最接近传入的起始逻辑块地址block的ext4_extent_idx。path[ppos]->p_idx指向这个ext4_extent_idx
		ext4_ext_binsearch_idx(inode, path + ppos, block);
		path[ppos].p_block = ext4_idx_pblock(path[ppos].p_idx);//物理块起始地址
		path[ppos].p_depth = i;//B+树层数
		path[ppos].p_ext = NULL;

        /*根据物理块地址path[ppos].p_block得到其代表的磁盘物理块映射的bh。这里有个隐藏重点，ext4 extent B+树每一个索引节点
        和叶子节点的ext4_extent_header、ext4_extent_idx、ext4_extent数据本质都是保存在磁盘里的，占一个物理块，4K大小。
        path[ppos].p_block来自ext4_idx_pblock(path[ppos].p_idx)，ext4_idx_pblock(path[ppos].p_idx)代表啥?path[ppos].p_idx是找到的
        逻辑块地址最接近传入的起始逻辑块地址block的ext4_extent_idx结构，ext4_idx_pblock(path[ppos].p_idx)是这个结构保存的物理块号，
        这个物理块保存的该索引节点下一层索引节点4K数据(ext4_extent_header+N个ext4_extent_idx结构)或者叶子节点的4K数据
        (ext4_extent_header+N个ext4_extent结构)。bh = sb_getblk(inode->i_sb, path[ppos].p_block)是映射这个物理块的4K数据到bh。
        
        ext4 extent B+树层层索引节点和叶子节点的4K数据都是保存在某个物理块(root节点除外)，层层索引节点和叶子节点是怎么建立联系的呢?
        就是上层索引节点ext4_extent_idx结构的物理块成员记录保存下层索引节点或者叶子节点4K的物理块号，当前这些层层索引节点和叶子节点
        肯定要有关系的，起始逻辑块地址一一对应，才会建立上下联系。这个是重点。
        */
		bh = sb_getblk(inode->i_sb, path[ppos].p_block);
		if (unlikely(!bh)) {
			ret = -ENOMEM;
			goto err;
		}
		if (!bh_uptodate_or_lock(bh)) {
			trace_ext4_ext_load_extent(inode, block,
						path[ppos].p_block);
			ret = bh_submit_read(bh);
			if (ret < 0) {
				put_bh(bh);
				goto err;
			}
		}
        //eh指向当前索引节点对应的下层索引节点或者叶子节点的头结点
		eh = ext_block_hdr(bh);
        //索引节点层数加1
		ppos++;
		if (unlikely(ppos > depth)) {
			put_bh(bh);
			EXT4_ERROR_INODE(inode,
					 "ppos %d > depth %d", ppos, depth);
			ret = -EIO;
			goto err;
		}
        /*隐藏知识点，此时ppos++了，ppos代表下一层索引节点或者叶子节点了*/
        //path[ppos].p_bh指向ppos这一层保存索引节点或者叶子节点 4K数据的物理块映射的bh
		path[ppos].p_bh = bh;
        //path[ppos].p_bh指向ppos这一层索引节点或者叶子节点的头结点
		path[ppos].p_hdr = eh;
		i--;

		ret = ext4_ext_check_block(inode, eh, i, bh);
		if (ret < 0)
			goto err;
	}

	path[ppos].p_depth = i;
	path[ppos].p_ext = NULL;
	path[ppos].p_idx = NULL;

	/* find extent */
  //利用二分法在ext4 extent B+树path[ppos]->p_hdr[]后边的ext4_extent[]数组中，找到起始逻辑块地址最接近传入的起始逻辑块地址block
  //的ext4_extent，令path[ppos]->p_ext指向这个ext4_extent。如果叶子结点没有一个ext4_extent结构，则path[ppos]->p_ext保持NULL
	ext4_ext_binsearch(inode, path + ppos, block);
	/* if not an empty leaf */
	if (path[ppos].p_ext)//物理块地址
		path[ppos].p_block = ext4_ext_pblock(path[ppos].p_ext);

	ext4_ext_show_path(inode, path);

	return path;

err:
	ext4_ext_drop_refs(path);
	if (alloc)
		kfree(path);
	return ERR_PTR(ret);
}

/*
 * ext4_ext_insert_index:
 * insert new index [@logical;@ptr] into the block at @curp;
 * check where to insert: before @curp or after @curp
 */
//把新的索引节点ext4_extent_idx结构(起始逻辑块地址logical,物理块号ptr)插入到ext4 extent B+树curp->p_idx指向的ext4_extent_idx结构前后。
//插入的本质很简单，把curp->p_idx或者(curp->p_idx+1)后边的所有ext4_extent_idx结构全向后移动一个ext4_extent_idx结构大小，把新的
//ext4_extent_idx插入curp->p_idx或者(curp->p_idx+1)原来的位置。
static int ext4_ext_insert_index(handle_t *handle, struct inode *inode,
				 struct ext4_ext_path *curp,
				 int logical, ext4_fsblk_t ptr)
{
	struct ext4_extent_idx *ix;
	int len, err;

	err = ext4_ext_get_access(handle, inode, curp);
	if (err)
		return err;

	if (unlikely(logical == le32_to_cpu(curp->p_idx->ei_block))) {
		EXT4_ERROR_INODE(inode,
				 "logical %d == ei_block %d!",
				 logical, le32_to_cpu(curp->p_idx->ei_block));
		return -EIO;
	}

	if (unlikely(le16_to_cpu(curp->p_hdr->eh_entries)
			     >= le16_to_cpu(curp->p_hdr->eh_max))) {
		EXT4_ERROR_INODE(inode,
				 "eh_entries %d >= eh_max %d!",
				 le16_to_cpu(curp->p_hdr->eh_entries),
				 le16_to_cpu(curp->p_hdr->eh_max));
		return -EIO;
	}
    //curp->p_idx是ext4 extent B+树起始逻辑块地址最接近传入的起始逻辑块地址map->m_lblk的ext4_extent_idx结构，现在是把新的
    //ext4_extent_idx(起始逻辑块地址是logical,起始物理块号ptr)插入到curp->p_idx指向的ext4_extent_idx结构前后。
	if (logical > le32_to_cpu(curp->p_idx->ei_block)) {
		/* insert after */
        //ext4 extent B+树索引节点的ext4_extent_idx结构的起始逻辑块地址，从左到右，依次增大，顺序排布。因此待插入的ext4_extent_idx
        //结构更大的话就要插入curp->p_idx这个ext4_extent_idx后边，(curp->p_idx + 1)这个ext4_extent_idx前边。插入前，下边memmove先把
        //(curp->p_idx+1)后边的所有ext4_extent_idx结构全向后移动一个ext4_extent_idx结构大小。
		ext_debug("insert new index %d after: %llu\n", logical, ptr);
		ix = curp->p_idx + 1;
	} else {
		/* insert before */
        //待插入的ext4_extent_idx结构起始逻辑块地址logical更小，就插入到curp->p_idx这个ext4_extent_idx前边。插入前，下边memmove先把
        //curp->p_idx后边的所有ext4_extent_idx结构全向后移动一个ext4_extent_idx结构大小。
		ext_debug("insert new index %d before: %llu\n", logical, ptr);
		ix = curp->p_idx;
	}
    //ix是curp->p_idx或者(curp->p_idx+1)
    //ix这个索引节点的ext4_extent_idx结构到索引节点最后一个ext4_extent_idx结构之间所有的ext4_extent_idx结构个数
	len = EXT_LAST_INDEX(curp->p_hdr) - ix + 1;
	BUG_ON(len < 0);
	if (len > 0) {
		ext_debug("insert new index %d: "
				"move %d indices from 0x%p to 0x%p\n",
				logical, len, ix, ix + 1);
        //把ix后边的len个ext4_extent_idx结构向后移动一次
		memmove(ix + 1, ix, len * sizeof(struct ext4_extent_idx));
	}

	if (unlikely(ix > EXT_MAX_INDEX(curp->p_hdr))) {
		EXT4_ERROR_INODE(inode, "ix > EXT_MAX_INDEX!");
		return -EIO;
	}
    //现在ix指向ext4_extent_idx结构空闲的，用它保存要插入的逻辑块地址logial和对应的物理块号
	ix->ei_block = cpu_to_le32(logical);
	ext4_idx_store_pblock(ix, ptr);
    //叶子结点ext4_extent_idx结构增加一个
	le16_add_cpu(&curp->p_hdr->eh_entries, 1);

	if (unlikely(ix > EXT_LAST_INDEX(curp->p_hdr))) {
		EXT4_ERROR_INODE(inode, "ix > EXT_LAST_INDEX!");
		return -EIO;
	}

	err = ext4_ext_dirty(handle, inode, curp);
	ext4_std_error(inode->i_sb, err);

	return err;
}

/*
 * ext4_ext_split:
 * inserts new subtree into the path, using free index entry
 * at depth @at:
 * - allocates all needed blocks (new leaf and all intermediate index blocks)
 * - makes decision where to split
 * - moves remaining extents and index entries (right to the split point)
 *   into the newly allocated blocks
 * - initializes subtree
 */



/*
1:首先确定ext4 extent B+树的分割点逻辑地址border。如果path[depth].p_ext不是ext4_extent B+树叶子节点节点
最后一个ext4 extent结构，则分割点逻辑地址border是path[depth].p_ext后边的ext4_extent起始逻辑块地址，即
border=path[depth].p_ext[1].ee_block。否则border是新插入ext4 extent B+树的ext4_extent的起始逻辑块地址，即newext->ee_block

2:ext4_extent B+树at那一层索引节点有空闲entry存放新的ext4_extent_idx，则针对at~depth(B+树深度)的每一层
都分配新的索引节点和叶子结点，每个索引节点和叶子结点都占一个block大小(4K)，分别保存N个ext4_extent_idx结构
和N个ext4_extent结构。在while (k--)那个循环，这些新分配的索引节点和叶子节点，B+树倒数第2层的那个索引节点的
第一个ext4_extent_idx的物理块号成员(ei_leaf_lo和ei_leaf_hi)记录的是新分配的保存叶子结点4K数据的物理块号
(代码是ext4_idx_store_pblock(fidx, oldblock))，第一个ext4_extent_idx的起始逻辑块地址是border
(代码是fidx->ei_block = border)。B+树倒数第3层的那个索引节点的第一个ext4_extent_idx的物理块号成员记录的
是保存倒数第2层的索引节点4K数据的物理块号，这层索引节点第一个ext4_extent_idx的起始逻辑块地址
是border(代码是fidx->ei_block = border)........其他类推。

at那一层新分配的索引节点的物理块号和起始逻辑块地址border是保存到ext4_extent B+树at层原有的
(path + at)->p_idx指向的索引节点的ext4_extent_idx结构前后的ext4_extent_idx结构。保存前把
(path + at)->p_idx指向的索引节点的ext4_extent_idx结构后的所有ext4_extent_idx结构向后移动
一个ext4_extent_idx结构大小，这就在(path + at)->p_idx指向的索引节点的ext4_extent_idx处腾
出了一个空闲的ext4_extent_idx结构大小空间，这点操作在ext4_ext_insert_index()完成。

3:要把ext4_extent B+树原来的at~depth层的 path[i].p_idx~path[depth-1].p_idx指向的ext4_extent_idx结构后边
的所有ext4_extent_idx结构 和 path[depth].p_ext指向的ext4_extent后的所有ext4_extent结构都对接移动到上边
针对ext4_extent B+树at~denth新分配索引节点和叶子节点物理块号映射bh内存。这是对原有的ext4 extent进行分配的重点。
*/

//ext4_ext_map_blocks()->ext4_ext_handle_uninitialized_extents()/ext4_ext_handle_unwritten_extents()->ext4_ext_convert_to_initialized()
//->ext4_split_extent()->ext4_split_extent_at()->ext4_ext_insert_extent()->ext4_ext_create_new_leaf()->ext4_ext_split()
/*
上边的解释没有诠释到本质。直击灵魂，为什么会执行到ext4_ext_insert_extent()->ext4_ext_create_new_leaf()->ext4_ext_split()?有什么意义?
首先，ext4_split_extent_at()函数中，把path[depth].p_ext指向的ext4_extent结构(即ex)的逻辑块范围分割成两段，两个ext4_extent结构。前边
的ext4_extent结构还是ex，只是逻辑块范围减少了。而后半段ext4_extent结构即newext就要插入插入到到ext4 extent B+树。ext4_ext_insert_extent()
函数中，如果此时ex所在叶子节点的ext4_extent结构爆满了，即if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max))不成立，但是
if (le32_to_cpu(newext->ee_block) > le32_to_cpu(fex->ee_block))成立，即newext的起始逻辑块地址小于ex所在叶子节点的最后一个ext4_extent
结构的起始逻辑块地址，则执行next = ext4_ext_next_leaf_block(path)等代码，回到上层索引节点，找到起始逻辑块地址更大的索引节点和叶子节点，
如果新的叶子节点的ext4_extent结构还是爆满，那就要执行ext4_ext_create_new_leaf()增大ext4_extent B+树层数了。

来到ext4_ext_create_new_leaf()函数，从最底层的索引节点开始向上搜索，找到有空闲entry的索引节点。如果找到则执行ext4_ext_split()。
如果找不到则执行ext4_ext_grow_indepth()在ext4_extent B+树root节点增加一层索引节点，然后也执行ext4_ext_split()。

当执行到ext4_ext_split()，at一层的ext4_extent B+树有空闲entry，则以从at层开始创建新的索引节点和叶子节点，建立这些新的索引节点和叶子节点
彼此的物理块号联系。我们假设ext4_ext_split()的if (path[depth].p_ext != EXT_MAX_EXTENT(path[depth].p_hdr))成立，则这样执行:

下边是把向新分配的叶子节点复制m个ext4_extent结构时，复制的第一个ext4_extent结构不是path[depth].p_ext，而是
它后边的 path[depth].p_ext[1]这个ext4_extent结构。并且，下边新创建的索引节点的第一个ext4_extent_idx结构的起始逻辑器块地址
都是border，即path[depth].p_ext[1]的逻辑块地址，也是path[depth].p_ext[1].ee_block。然后向新传创建的索引节点的第2个
ext4_extent_idx结构处及之后复制m个ext4_extent_idx结构。新传创建的索引节点的第一个ext4_extent_idx的起始逻辑块地址是border，
单独使用，作为分割点的ext4_extent_idx结构。如此，后续执行ext4_ext_find_extent(newext->ee_block)在老的ext4_extent B+树找到的
path[depth].p_ext指向的ext4_extent还是老的，但是path[depth].p_ext后边的m个ext4_extent结构移动到了新分配的叶子节点，
path[depth].p_ext所在叶子节点就有空间了，newext就插入到path[depth].p_ext指向的ext4_extent叶子节点后边。这段代码在ext4_ext_insert_extent()的
has_space 的if (!nearex)........} else{......}的else分支

如果ext4_ext_split()的if (path[depth].p_ext != EXT_MAX_EXTENT(path[depth].p_hdr))不成立，则这样执行:
不会向新分配的叶子节点复制ext4_extent结构时，m是0，因为path[depth].p_ext就是叶子节点最后一个ext4_extent
结构，下边的m = EXT_MAX_EXTENT(path[depth].p_hdr) - path[depth].p_ext++=0。并且，下边新创建的索引节点的第一个ext4_extent_idx结构
的起始逻辑器块地址都是newext->ee_block。这样后续执行ext4_ext_find_extent()在ext4_extent B+树就能找到起始逻辑块地址是
newext->ee_block的层层索引节点了，完美匹配。那叶子节点呢?这个分支没有向新的叶子节点复制ext4_extent结构，空的，
ext4_ext_find_extent()执行后，path[ppos].depth指向新的叶子节点的头结点，此时直接令该叶子节点的第一个ext4_extent结构的
逻辑块地址是newext->ee_block，完美!这段代码在ext4_ext_insert_extent()的has_space 的if (!nearex)分支。

因此，我们看到ext4_ext_split()最核心的作用是:at一层的ext4_extent B+树有空闲entry，则以从at层开始创建新的索引节点和叶子节点，
建立这些新的索引节点和叶子节点彼此的物理块号联系。然后把path[depth].p_ext后边的ext4_extent结构移动到新的叶子节点，把
path[at~depth-1].p_idx这些索引节点后边的ext4_extent_idx结构依次移动到新创建的索引节点。这样要么老的path[depth].p_ext所在叶子节点
有了空闲的ext4_extent entry，把newex插入到老的path[depth].p_ext所在叶子节点某处ext4_extent结构出即可。或者新创建的at~denth的索引节点
和叶子节点，有大量空闲的entry，这些索引节点的起始逻辑块地址还是newext->ee_block，则直接把newext插入到新创建的叶子节点第一个
ext4_extent结构即可。
*/

static int ext4_ext_split(handle_t *handle, struct inode *inode,
			  unsigned int flags,
			  struct ext4_ext_path *path,
//newext是要插入ext4_extent B+树的ext4_extent，在ext4_extent B+树的第at层插入newext，第at层的索引节点有空闲entry
			  struct ext4_extent *newext, int at)
{
	struct buffer_head *bh = NULL;
	int depth = ext_depth(inode);
	struct ext4_extent_header *neh;
	struct ext4_extent_idx *fidx;
	int i = at, k, m, a;
	ext4_fsblk_t newblock, oldblock;
	__le32 border;
	ext4_fsblk_t *ablocks = NULL; /* array of allocated blocks */
	int err = 0;

	/* make decision: where to split? */
	/* FIXME: now decision is simplest: at current extent */

	/* if current leaf will be split, then we should use
	 * border from split point */
	if (unlikely(path[depth].p_ext > EXT_MAX_EXTENT(path[depth].p_hdr))) {
		EXT4_ERROR_INODE(inode, "p_ext > EXT_MAX_EXTENT!");
		return -EIO;
	}

    //path[depth].p_ext是ext4 extent B+树叶子节点中，逻辑块地址最接近map->m_lblk这个起始逻辑块地址的ext4_extent
	if (path[depth].p_ext != EXT_MAX_EXTENT(path[depth].p_hdr)) {
        //path[depth].p_ext不是叶子节点最后一个ext4_extent结构，那以它后边的ext4_extent即的起始逻辑块地址作为分割点，即border
        /*走到这个分支，下边是把向新分配的叶子节点复制m个ext4_extent结构时，复制的第一个ext4_extent结构不是path[depth].p_ext，而是
        它后边的 path[depth].p_ext[1]这个ext4_extent结构。并且，下边新创建的索引节点的第一个ext4_extent_idx结构的起始逻辑器块地址
        都是border，即path[depth].p_ext[1]的逻辑块地址，也是path[depth].p_ext[1].ee_block。然后向新传创建的索引节点的第2个
        ext4_extent_idx结构处及之后复制m个ext4_extent_idx结构。新传创建的索引节点的第一个ext4_extent_idx的起始逻辑块地址是border，
        单独使用，作为分割点的ext4_extent_idx结构。如此，后续执行ext4_ext_find_extent(newext->ee_block)在老的ext4_extent B+树找到的
        path[depth].p_ext指向的ext4_extent还是老的，但是path[depth].p_ext后边的m个ext4_extent结构移动到了新分配的叶子节点，
        path[depth].p_ext所在叶子节点就有空间了，newext就插入到path[depth].p_ext指向的ext4_extent叶子节点后边。这段代码在
        ext4_ext_insert_extent()的has_space 的if (!nearex)........} else{......}的else分支*/
		border = path[depth].p_ext[1].ee_block;
		ext_debug("leaf will be split."
				" next leaf starts at %d\n",
				  le32_to_cpu(border));
	} else {
	    //这里说明path[depth].p_ext指向的是叶子节点最后一个ext4_extent结构
	   /*走到这个分支，下边不会向新分配的叶子节点复制ext4_extent结构时，m是0，因为path[depth].p_ext就是叶子节点最后一个ext4_extent
	   结构，下边的m = EXT_MAX_EXTENT(path[depth].p_hdr) - path[depth].p_ext++=0。并且，下边新创建的索引节点的第一个ext4_extent_idx结构
	   的起始逻辑器块地址都是newext->ee_block。这样后续执行ext4_ext_find_extent()在ext4_extent B+树就能找到起始逻辑块地址是
	   newext->ee_block的层层索引节点了，完美匹配。那叶子节点呢?这个分支没有向新的叶子节点复制ext4_extent结构，空的，
	   ext4_ext_find_extent()执行后，path[ppos].depth指向新的叶子节点的头结点，此时直接令该叶子节点的第一个ext4_extent结构的
	   逻辑块地址是newext->ee_block，完美!这段代码在ext4_ext_insert_extent()的has_space 的if (!nearex)分支。*/
		border = newext->ee_block;
		ext_debug("leaf will be added."
				" next leaf starts at %d\n",
				le32_to_cpu(border));
	}

	/*
	 * If error occurs, then we break processing
	 * and mark filesystem read-only. index won't
	 * be inserted and tree will be in consistent
	 * state. Next mount will repair buffers too.
	 */

	/*
	 * Get array to track all allocated blocks.
	 * We need this to handle errors and free blocks
	 * upon them.
	 */
	//依照ext4_extent B+树层数分配depth个block
	ablocks = kzalloc(sizeof(ext4_fsblk_t) * depth, GFP_NOFS);
	if (!ablocks)
		return -ENOMEM;

	/* allocate all needed blocks */
	ext_debug("allocate %d blocks for indexes/leaf\n", depth - at);
    //分配(depth - at)个物理块，newext是在ext4 extent B+的第at层插入，从at层到depth层，每层分配一个物理块
	for (a = 0; a < depth - at; a++) {
        //从ext4文件系统元数据区分配一个物理块，返回它的物理块号。应该是4K大小，保存ext4 extent B+树索引节点或者叶子结点的N个ext4_extent_idx、ext4_extent结构
		newblock = ext4_ext_new_meta_block(handle, inode, path,
						   newext, &err, flags);
		if (newblock == 0)
			goto cleanup;
        //分配的物理块的块号保存到ablocks
		ablocks[a] = newblock;
	}

	/* initialize new leaf */
	newblock = ablocks[--a];
	if (unlikely(newblock == 0)) {
		EXT4_ERROR_INODE(inode, "newblock == 0!");
		err = -EIO;
		goto cleanup;
	}
	bh = sb_getblk(inode->i_sb, newblock);
	if (unlikely(!bh)) {
		err = -ENOMEM;
		goto cleanup;
	}
	lock_buffer(bh);

	err = ext4_journal_get_create_access(handle, bh);
	if (err)
		goto cleanup;

    //neh指向新分配的叶子节点首内存的头结点ext4_extent_header结构
	neh = ext_block_hdr(bh);
	neh->eh_entries = 0;
	neh->eh_max = cpu_to_le16(ext4_ext_space_block(inode, 0));
	neh->eh_magic = EXT4_EXT_MAGIC;
	neh->eh_depth = 0;

	/* move remainder of path[depth] to the new leaf */
	if (unlikely(path[depth].p_hdr->eh_entries !=
		     path[depth].p_hdr->eh_max)) {
		EXT4_ERROR_INODE(inode, "eh_entries %d != eh_max %d!",
				 path[depth].p_hdr->eh_entries,
				 path[depth].p_hdr->eh_max);
		err = -EIO;
		goto cleanup;
	}
	/* start copy from next extent */
    //从path[depth].p_ext后边的ext4_extent结构到叶子节点最后一个ext4_extent结构之间，一共有m个ext4_extent结构
    /*这个有个隐藏点，这里是path[depth].p_ext++，执行后path[depth].p_ext已经指向了下一个ext4_extent结构了，这样下边memmove(ex, path[depth].p_ext,....)
     向ex复制的m个ext4_extent结构，并不包含path[depth].p_ext最初指向的ext4_extent。还有一个隐藏点，如果path[depth].p_ext本身就是老的
     叶子节点的最后一个ext4_extent结构，下边计算出的m是0，那就不会再向新的叶子节点赋值ext4_extent结构了*/
	m = EXT_MAX_EXTENT(path[depth].p_hdr) - path[depth].p_ext++;
	ext4_ext_show_move(inode, path, newblock, depth);
	if (m) {
		struct ext4_extent *ex;
        //ex指向新分配的ext4 extent B+树叶子节点的第一个ext4_extent结构
		ex = EXT_FIRST_EXTENT(neh);
        //把path[depth].p_ext叶子节点path[depth].p_ext后的m个ext4_extent结构移动到新分配的叶子节点ex开头
		memmove(ex, path[depth].p_ext, sizeof(struct ext4_extent) * m);
        //ex叶子节点增肌了m个ext4_extent结构
		le16_add_cpu(&neh->eh_entries, m);
	}

	ext4_extent_block_csum_set(inode, neh);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	err = ext4_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto cleanup;
	brelse(bh);
	bh = NULL;

	/* correct old leaf */
	if (m) {
		err = ext4_ext_get_access(handle, inode, path + depth);
		if (err)
			goto cleanup;
        //path[depth].p_hdr这个叶子节点的ext4_extent结构减少m个
		le16_add_cpu(&path[depth].p_hdr->eh_entries, -m);
        //叶子节点的ext4_extent个数减少，标记叶子节点对应的bh脏
		err = ext4_ext_dirty(handle, inode, path + depth);
		if (err)
			goto cleanup;

	}

	/* create intermediate indexes */
    //ext4_extent B+树at那一层的索引节点到最后一层索引节点之间的层数，就是从at开始有多少层索引节点
	k = depth - at - 1;
	if (unlikely(k < 0)) {
		EXT4_ERROR_INODE(inode, "k %d < 0!", k);
		err = -EIO;
		goto cleanup;
	}
	if (k)
		ext_debug("create %d intermediate indices\n", k);
	/* insert new index into current index block */
	/* current depth stored in i var */
    //i初值是ext4_extent B+树最后一层索引节点
	i = depth - 1;
    //循环k次保证把at那一层的ext4_extent B+树索引节点到最后一层索引节点path[i].p_idx指向的ext4_extent_idx结构到最后一个ext4_extent_idx结构之间
    //所有的ext4_extent_idx结构，都复制到ablocks[--a]即newblock这个物理块映射bh。注意，是从ext4_extent B+树最下层的索引节点向上开始
    //复制，因为i的初值是depth - 1，这是ext4_extent B+树最下边一层索引节点的层数
	while (k--) {
		oldblock = newblock;
        //新取出一个物理块对应的块号newblock
		newblock = ablocks[--a];
        //newblock物理块映射的bh
		bh = sb_getblk(inode->i_sb, newblock);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			goto cleanup;
		}
		lock_buffer(bh);

		err = ext4_journal_get_create_access(handle, bh);
		if (err)
			goto cleanup;
        //neh指向newblock这个物理块映射的bh的内存首地址，开头的是ext4_extent B+树索引节点的头ext4_extent_header
		neh = ext_block_hdr(bh);
		neh->eh_entries = cpu_to_le16(1);
		neh->eh_magic = EXT4_EXT_MAGIC;
        //叶子结点能容纳的ext4_extent_idx结构个数，ext4_extent B+树叶子节点数据保存在newblock这个物理块，4K大小
		neh->eh_max = cpu_to_le16(ext4_ext_space_block_idx(inode, 0));
        //索引节点所处B+树层数
		neh->eh_depth = cpu_to_le16(depth - i);
        //fidx指向newblock这个物理块对应的索引节点的第一个ext4_extent_idx结构
		fidx = EXT_FIRST_INDEX(neh);
        //起始逻辑块地址是上边的分割点逻辑点地址
		fidx->ei_block = border;
        /*重点，第一次到这里，oldblock(即newblock)是保存上边新分配的叶子节点4K数据的物理块号，fidx指向最后一层索引节点
         第一个ext4_extent_idx结构，这里是把新分配的保存叶子结点数据的物理块号newblock保存到最后一层索引节点第一个索引节点的
         ext4_extent_idx结构中。后续的循环，都是上层索引节点的第一个ext4_extent_idx结构记录下层索引节点4K数据保存的物理块号。
         说白了，ext4_ext_split()函数把原有的ext4_extent B+树at~depth层的索引节点和叶子结点的后半段数据移动到新创建的
         索引节点和叶子结点中。这里是在上层索引节点中记录下层索引节点或者叶子结点4K数据保存的物理块号*/
		ext4_idx_store_pblock(fidx, oldblock);

		ext_debug("int.index at %d (block %llu): %u -> %llu\n",
				i, newblock, le32_to_cpu(border), oldblock);

		/* move remainder of path[i] to the new index block */
		if (unlikely(EXT_MAX_INDEX(path[i].p_hdr) !=
					EXT_LAST_INDEX(path[i].p_hdr))) {
			EXT4_ERROR_INODE(inode,
					 "EXT_MAX_INDEX != EXT_LAST_INDEX ee_block %d!",
					 le32_to_cpu(path[i].p_ext->ee_block));
			err = -EIO;
			goto cleanup;
		}
		/* start copy indexes */
       //path[i].p_hdr这一层索引节点中，从path[i].p_idx指向的ext4_extent_idx结构到最后一个ext4_extent_idx结构之间ext4_extent_idx个数
       /*隐藏点，path[i].p_idx++，执行后path[i].p_idx指向下一个ext4_extent_idx结构。这样下边memmove(++fidx, path[i].p_idx...)向
        fidx复制的m个ext4_extent_idx结构，并不包含path[i].p_idx最初指向的ext4_extent_idx。还有一个隐藏点，如果path[i].p_idx指向的就是
        老的索引节点的最后一个ext4_extent_idx，则下边计算出来的m是0，那就不会向新的索引节点复制ext4_extent_idx结构了。*/
		m = EXT_MAX_INDEX(path[i].p_hdr) - path[i].p_idx++;
		ext_debug("cur 0x%p, last 0x%p\n", path[i].p_idx,
				EXT_MAX_INDEX(path[i].p_hdr));
		ext4_ext_show_move(inode, path, newblock, i);
		if (m) {
            //把path[i].p_idx后边的m个ext4_extent_idx结构赋值到newblock这个物理块对应的索引节点开头的第1个ext4_extent_idx后边，即fidx指向的内存
            /*隐藏点，这里是++fid，即fidx指向的新的索引节点的第2个ext4_extent_idx位置处，这是向新的索引节点第2个ext4_extent_idx处及后边
             赋值m个ext4_extent_idx结构*/
			memmove(++fidx, path[i].p_idx,
				sizeof(struct ext4_extent_idx) * m);
            //newblock这个物理块对应的新的索引节点增加了m个ext4_extent_idx结构
			le16_add_cpu(&neh->eh_entries, m);
		}
		ext4_extent_block_csum_set(inode, neh);
		set_buffer_uptodate(bh);
		unlock_buffer(bh);

		err = ext4_handle_dirty_metadata(handle, inode, bh);
		if (err)
			goto cleanup;
		brelse(bh);
		bh = NULL;

		/* correct old index */
		if (m) {
			err = ext4_ext_get_access(handle, inode, path + i);
			if (err)
				goto cleanup;
            //path[i].p_hdr指向的ext4 extent B+树那一层索引节点减少了m个ext4_extent_idx结构
			le16_add_cpu(&path[i].p_hdr->eh_entries, -m);
            //path[i].p_hdr指向的ext4 extent B+树那一层索引节点，索引节点数据有变化，保存这一层索引节点数据的物理块要标记脏
			err = ext4_ext_dirty(handle, inode, path + i);
			if (err)
				goto cleanup;
		}
        //i--表示下次循环，把上一层ext4_extent B+树索引节点的path[i].p_idx指向的ext4_extent_idx结构到最后一个ext4_extent_idx结构之间
        //所有的ext4_extent_idx结构，复制到ablocks[--a]即newblock这个物理块映射bh
		i--;
	}

	/* insert new index */
/*把新的索引节点ext4_extent_idx结构(起始逻辑块地址border,物理块号newblock)插入到ext4 extent B+树at那一层索引节点(path + at)->p_idx指向
的ext4_extent_idx结构前后。在这里时，newblock是上边新分配的at~depth层的索引节点和叶子结点中，最靠上，也就是at那一层索引节点的物理块号。
上边已经把令这些新分配的索引节点和叶子结点，上层记录下层的物理块号。这里再把at那一层新分配的索引节点的物理块号newlbock记录到ext4 extent
B+树原来的at那一层的(path + at)->p_idx指向的ext4_extent_idx结构前后。ext4 extentB+树原来的at那一层有空闲的entry，就是有空闲的位置存放
新的索引节点。*/
	err = ext4_ext_insert_index(handle, inode, path + at,
				    le32_to_cpu(border), newblock);

cleanup:
	if (bh) {
		if (buffer_locked(bh))
			unlock_buffer(bh);
		brelse(bh);
	}

	if (err) {
		/* free all allocated blocks in error case */
		for (i = 0; i < depth; i++) {
			if (!ablocks[i])
				continue;
			ext4_free_blocks(handle, inode, NULL, ablocks[i], 1,
					 EXT4_FREE_BLOCKS_METADATA);
		}
	}
	kfree(ablocks);

	return err;
}

/*
 * ext4_ext_grow_indepth:
 * implements tree growing procedure:
 * - allocates new block
 * - moves top-level data (index block or leaf) into the new block
 * - initializes new top-level, creating index that points to the
 *   just created block
 */
//针对ex->ee_block分配一个新的物理块，作为新的索引节点或者叶子节点添加到ext4 extent B+树根节点下方，这样相当于跟ext4 extent B+树增加了
//一层新的节点
static int ext4_ext_grow_indepth(handle_t *handle, struct inode *inode,
				 unsigned int flags,
				 struct ext4_extent *newext)
{
	struct ext4_extent_header *neh;
	struct buffer_head *bh;
	ext4_fsblk_t newblock;
	int err = 0;
    //找到或分配ex->ee_block映射的物理块，返回物理块号newblock
	newblock = ext4_ext_new_meta_block(handle, inode, NULL,
		newext, &err, flags);
	if (newblock == 0)
		return err;
    //newblock物理块映射的bh
	bh = sb_getblk(inode->i_sb, newblock);
	if (unlikely(!bh))
		return -ENOMEM;
	lock_buffer(bh);

	err = ext4_journal_get_create_access(handle, bh);
	if (err) {
		unlock_buffer(bh);
		goto out;
	}
    /*
    上边针对ex->ee_block分配一个新的物理块，物理块号是newblock，4K大小。这这个newblock的物理块下边正是作为新的叶子结点或
    索引节点添加到ext4 extent B+树下方，是树的第2层。
     
    下边有两个重要操作，把ext4 extent B+树根节点的复制到newblock对应的bh内存，newblock将来作为新的叶子结点或者索引节点，
     就放在根节点下方。neh = ext_block_hdr(bh)到neh->eh_magic = EXT4_EXT_MAGIC就是对这个新的节点赋值。下边的neh = ext_inode_hdr(inode)
     到le16_add_cpu(&neh->eh_depth, 1)是更新ext4 extent B+根节点的数据。因为此时newblock作为新的叶子结点或者索引节点添加到了
     根节点下边，ext4_idx_store_pblock(EXT_FIRST_INDEX(neh), newblock)就是根节点的第一个ext4_extent_idx节点记录newblock这个
     新的叶子结点或者索引节点的物理块号。

     有一个隐藏点是，此时ext4 extent B+树根节点只有第一个ext4_extent_idx结构是有效的，该结构的物理块号成员保存的正是newblock的物理
     块号*/
    
	/* move top-level index/leaf into new block */
    //把ext4 extent B+树的根节点复制到bh->b_data。下边把这个bh->b_data指向的内存的数据将放到ext4 extent B+树下边，
    //作为ext4 extent B+树下边的索引节点或者叶子结点
	memmove(bh->b_data, EXT4_I(inode)->i_data,
		sizeof(EXT4_I(inode)->i_data));

	/* set size of new block */
    //neh指向bh首地址，这些内存的数据是前边向bh->b_data复制的ext4 extent B+树的根节点数据
	neh = ext_block_hdr(bh);
	/* old root could have indexes or leaves
	 * so calculate e_max right way */
	if (ext_depth(inode))//如果ext4 extent B+树有索引节点，neh指向的内存作为索引节点
		neh->eh_max = cpu_to_le16(ext4_ext_space_block_idx(inode, 0));
	else//如果ext4 extent B+树没有索引节点，只有根节点，neh指向的内存作为叶子结点
		neh->eh_max = cpu_to_le16(ext4_ext_space_block(inode, 0));
	neh->eh_magic = EXT4_EXT_MAGIC;
	ext4_extent_block_csum_set(inode, neh);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	err = ext4_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto out;

	/* Update top-level index: num,max,pointer */
    //现在neh又指向ext4 extent B+根节点
	neh = ext_inode_hdr(inode);
    //根节点现在只有一个叶子节点或者索引节点，即物理块号是newblock的那个叶子结点或索引节点
	neh->eh_entries = cpu_to_le16(1);
    //newblock这个物理块号记录到根节点的第一个ext4_extent_idx结构里，这样就建立了ext4 extent B+根节点跟新添加的物理块号是newblock
    //的叶子结点或索引节点的联系
	ext4_idx_store_pblock(EXT_FIRST_INDEX(neh), newblock);
    //如果neh->eh_depth是0，说明之前ext4 extent B+树深度是0，即只有根节点
	if (neh->eh_depth == 0) {
		/* Root extent block becomes index block */
        //以前B+树只有根节点，neh->eh_max按照4k/ext4_extent结构大小计算，现在B+树根节点下添加了newblock这个叶子或索引节点
        //根节点其实成了根索引节点，neh->eh_max要按照4k/ext4_extent_idx结构大小计算
		neh->eh_max = cpu_to_le16(ext4_ext_space_root_idx(inode, 0));
        //以前B+树只有根节点，没有索引节点，根节点都是ext4_extent结构，现在B+树根节点下添加了newblock这个叶子或索引节点，
        //根节点其实成了根索引节点，因此原来第一个ext4_extent结构要换成ext4_extent_idx结构，下边赋值就是把ext4_extent的逻辑块首地址
        //赋值给ext4_extent_idx的逻辑块首地址
		EXT_FIRST_INDEX(neh)->ei_block =
			EXT_FIRST_EXTENT(neh)->ee_block;
	}
	ext_debug("new root: num %d(%d), lblock %d, ptr %llu\n",
		  le16_to_cpu(neh->eh_entries), le16_to_cpu(neh->eh_max),
		  le32_to_cpu(EXT_FIRST_INDEX(neh)->ei_block),
		  ext4_idx_pblock(EXT_FIRST_INDEX(neh)));
    //ext4 extent B+树增加了一层索引节点或叶子结点，即物理块号是newblock的那个
	le16_add_cpu(&neh->eh_depth, 1);
	ext4_mark_inode_dirty(handle, inode);
out:
	brelse(bh);

	return err;
}

/*
 * ext4_ext_create_new_leaf:
 * finds empty index and adds new leaf.
 * if no free index is found, then it requests in-depth growing.
 */
static int ext4_ext_create_new_leaf(handle_t *handle, struct inode *inode,
				    unsigned int flags,
				    struct ext4_ext_path *path,
				    struct ext4_extent *newext)
{
	struct ext4_ext_path *curp;
	int depth, i, err = 0;

repeat:
	i = depth = ext_depth(inode);

	/* walk up to the tree and look for free index entry */
	curp = path + depth;//curp首先指向ext4 extent B+树叶子节点
	
	//该while是从ext4 extent B+树叶子节点开始，向上一直到索引节点，看索引节点或者叶子节点的ext4_extent_idx或ext4_extent个数是否大于
	//最大限制eh_max，超出限制EXT_HAS_FREE_INDEX(curp)返回0，否则返回1.从该while循环退出时，有两种可能，1:curp非NULL，curp指向的索引
	//节点或叶子节点有空闲条目entry，2:i是0，ext4 extent B+树索引节点或叶子节点ext4_extent_idx或ext4_extent个数爆满，没有空闲条目entry
	while (i > 0 && !EXT_HAS_FREE_INDEX(curp)) {
		i--;
		curp--;
	}

	/* we use already allocated block for index block,
	 * so subsequent data blocks should be contiguous */
	//ext4 extent B+树索引节点或者叶子节点 有 空闲条目entry,此时的i表示ext4 extent B+树有空闲entry的那一层索引节点或叶子结点
	//newext是要插入ext4_extent B+树的ext4_extent，插入ext4_extent B+树的第i层
	if (EXT_HAS_FREE_INDEX(curp)) {
        /***/
		/* if we found index with free entry, then use that
		 * entry: create all needed subtree and add new leaf */
		err = ext4_ext_split(handle, inode, flags, path, newext, i);
		if (err)
			goto out;

		/* refill path */
		ext4_ext_drop_refs(path);
        //对ext4_extent B+树做了分割，这里重新在里边查找起始逻辑块地址接近newext->ee_block的索引节点和叶子结点
		path = ext4_ext_find_extent(inode,
				    (ext4_lblk_t)le32_to_cpu(newext->ee_block),
				    path);
		if (IS_ERR(path))
			err = PTR_ERR(path);
	} else {
	/*到这个分支，ext4 extent B+树索引节点的ext4_extent_idx和叶子节点的ext4_extent个数全爆满，都没有空闲条目entry，
	  就是说ext4 extent B+树全爆满了，只能增加执行ext4_ext_grow_indepth()增加ext4 extent B+树深度了。理解这点非常关键*/

        //针对newext->ee_block分配一个新的物理块，作为新的索引节点或者叶子节点添加到ext4 extent B+树根节点下方，这样相当于
        //跟ext4 extent B+树增加了一层新的节点
		/* tree is full, time to grow in depth */
		err = ext4_ext_grow_indepth(handle, inode, flags, newext);
		if (err)
			goto out;

		/* refill path */
		ext4_ext_drop_refs(path);
        //到这里，ext4 extent B+树根节点下方增加了一层新的索引或者叶子节点，再重新在ext4 extent B+树find_extent。注意，ext4 extent B+树
        //此时仅仅是增加了一层索引节点或者叶子节点，仅仅是树深层增加一层，其他并没有变化。索引ext4_ext_find_extent()是肯定能找到
        //起始逻辑块地址接近newext->ee_block的层层索引节点或者叶子节点的ext4_extent_idx或ext4_extent结构。并且，此时至少B+树根节点
        //下方新增加的节点有空闲entry。如果此时ext4 extent B+树叶子节点有空闲entry，则从ext4_ext_create_new_leaf()返回后可直接把
        //newext插入叶子节点。如果叶子节点entry爆满，即下边的if (path[depth].p_hdr->eh_entries == path[depth].p_hdr->eh_max)成立，
        //那就goto repeat分支，执行ext4_ext_split()分割ext4_extent B+树，创建新的叶子结点或者索引节点，使得newext能插入进去。
		path = ext4_ext_find_extent(inode,
				   (ext4_lblk_t)le32_to_cpu(newext->ee_block),
				    path);
		if (IS_ERR(path)) {
			err = PTR_ERR(path);
			goto out;
		}

		/*
		 * only first (depth 0 -> 1) produces free space;
		 * in all other cases we have to split the grown tree
		 */
		depth = ext_depth(inode);
        //path[depth].p_hdr指向的叶子结点保存ext4_extent结构达到eh_max，则goto repeat寻找有空闲entry的索引节点，然后分割
        //ext4 extent B+树。这if大概率是成立的，因为之所以执行到ext4_ext_create_new_leaf()，就是因为很多叶子结点的ext4_extent结构爆满了
        //而上边ext4_ext_find_extent()只是在ext4 extent B+树root节点下边增加了一层索引节点(或者叶子节点)
		if (path[depth].p_hdr->eh_entries == path[depth].p_hdr->eh_max) {
			/* now we need to split */
			goto repeat;
		}
	}

out:
	return err;
}

/*
 * search the closest allocated block to the left for *logical
 * and returns it at @logical + it's physical address at @phys
 * if *logical is the smallest allocated block, the function
 * returns 0 at @phys
 * return value contains 0 (success) or error code
 */
//logical = le32_to_cpu(ex->ee_block) + ee_len - 1
static int ext4_ext_search_left(struct inode *inode,
				struct ext4_ext_path *path,
				ext4_lblk_t *logical, ext4_fsblk_t *phys)//logical就是map->m_lblk
{
	struct ext4_extent_idx *ix;
	struct ext4_extent *ex;
	int depth, ee_len;

	if (unlikely(path == NULL)) {
		EXT4_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EIO;
	}
	depth = path->p_depth;
	*phys = 0;

	if (depth == 0 && path->p_ext == NULL)
		return 0;

	/* usually extent in the path covers blocks smaller
	 * then *logical, but it can be that extent is the
	 * first one in the file */

	ex = path[depth].p_ext;
	ee_len = ext4_ext_get_actual_len(ex);
    //logical即map->m_lblk小于path[depth].p_ext的起始逻辑块地址
	if (*logical < le32_to_cpu(ex->ee_block)) {
        //这是判断ext4 extent B+树叶子节点的第一个ext4_extent结构是不是path[depth].p_ext指向的ext4_extent，为什么二者会相等呢?????????
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != ex)) {
			EXT4_ERROR_INODE(inode,
					 "EXT_FIRST_EXTENT != ex *logical %d ee_block %d!",
					 *logical, le32_to_cpu(ex->ee_block));
			return -EIO;
		}
		while (--depth >= 0) {
            //ext4 extent B+树的索引节点的头结点
			ix = path[depth].p_idx;
            //ext4 extent B+树的索引节点的第一个ext4_extent_idx结构是不是path[depth].p_idx指向的那个ext4_extent_idx，为什么二者会相等呢?????????
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				EXT4_ERROR_INODE(inode,
				  "ix (%d) != EXT_FIRST_INDEX (%d) (depth %d)!",
				  ix != NULL ? le32_to_cpu(ix->ei_block) : 0,
				  EXT_FIRST_INDEX(path[depth].p_hdr) != NULL ?
		le32_to_cpu(EXT_FIRST_INDEX(path[depth].p_hdr)->ei_block) : 0,
				  depth);
				return -EIO;
			}
		}
		return 0;
	}

	if (unlikely(*logical < (le32_to_cpu(ex->ee_block) + ee_len))) {
		EXT4_ERROR_INODE(inode,
				 "logical %d < ee_block %d + ee_len %d!",
				 *logical, le32_to_cpu(ex->ee_block), ee_len);
		return -EIO;
	}
    //logical更新为ex->ee_block+ee_len
	*logical = le32_to_cpu(ex->ee_block) + ee_len - 1;
	*phys = ext4_ext_pblock(ex) + ee_len - 1;
	return 0;
}

/*
 * search the closest allocated block to the right for *logical
 * and returns it at @logical + it's physical address at @phys
 * if *logical is the largest allocated block, the function
 * returns 0 at @phys
 * return value contains 0 (success) or error code
 */
//path[depth].p_ext不是叶子节点最后一个ext4_extent结构，则找到path[depth].p_ext后边的ext4_extent结构给ret_ex，ret_ex的起始逻辑块地址赋于
//logical 。否则，选择ext4 extent B+最左边的索引节点下的叶子节点的第一个ext4_extent结构给ret_ex，ret_ex的起始逻辑块地址赋于logical
static int ext4_ext_search_right(struct inode *inode,
				 struct ext4_ext_path *path,
				 ext4_lblk_t *logical, ext4_fsblk_t *phys,//logical是map->m_lblk
				 struct ext4_extent **ret_ex)
{
	struct buffer_head *bh = NULL;
	struct ext4_extent_header *eh;
	struct ext4_extent_idx *ix;
	struct ext4_extent *ex;
	ext4_fsblk_t block;
	int depth;	/* Note, NOT eh_depth; depth from top of tree */
	int ee_len;

	if (unlikely(path == NULL)) {
		EXT4_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EIO;
	}
	depth = path->p_depth;
	*phys = 0;

	if (depth == 0 && path->p_ext == NULL)
		return 0;

	/* usually extent in the path covers blocks smaller
	 * then *logical, but it can be that extent is the
	 * first one in the file */

	ex = path[depth].p_ext;
	ee_len = ext4_ext_get_actual_len(ex);
	if (*logical < le32_to_cpu(ex->ee_block)) {
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != ex)) {
			EXT4_ERROR_INODE(inode,
					 "first_extent(path[%d].p_hdr) != ex",
					 depth);
			return -EIO;
		}
		while (--depth >= 0) {
			ix = path[depth].p_idx;
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				EXT4_ERROR_INODE(inode,
						 "ix != EXT_FIRST_INDEX *logical %d!",
						 *logical);
				return -EIO;
			}
		}
		goto found_extent;
	}

	if (unlikely(*logical < (le32_to_cpu(ex->ee_block) + ee_len))) {
		EXT4_ERROR_INODE(inode,
				 "logical %d < ee_block %d + ee_len %d!",
				 *logical, le32_to_cpu(ex->ee_block), ee_len);
		return -EIO;
	}
    //ex不是叶子节点最后一个ext4_extent结构
	if (ex != EXT_LAST_EXTENT(path[depth].p_hdr)) {
		/* next allocated block in this leaf */
        //ext4_extent B+树叶子节点选择ex后边的ext4_extent结构，这就是要选择的ext4_extent
		ex++;
		goto found_extent;
	}

    /*到这里说明ex是叶子结点最后一个ext4_extent结构，那就从B+树最底层索引节点--depth向上搜索，直到path[depth].p_idx不是
     索引节点最后一个ext4_extent_idx结构，goto got_index分支。再从B+树depth索引节点从上向下搜索，找到每一层叶子结点最靠左的
     ext4_extent_idx结构，再找到最底层索引节点最靠左ext4_extent_idx结构的第一个ext4_extent结构，作为找到的逻辑块地址*/
    
	/* go up and search for index to the right */
    //无法从ext4_extent B+树叶子结点找到合适的ext4_extent结构，去索引节点找
	while (--depth >= 0) {//depth--指向ext4_extent B+树的索引节点
	    //ix是ext4_extent B+树索引节点的ext4_extent_idx
		ix = path[depth].p_idx;
        //path[depth].p_idx指向的ext4_extent_idx不是索引节点最后一个
		if (ix != EXT_LAST_INDEX(path[depth].p_hdr))
			goto got_index;
	}

	/* we've gone up to the root and found no index to the right */
	return 0;

got_index:
	/* we've found index to the right, let's
	 * follow it and find the closest allocated
	 * block to the right */
	//ix指向ext4 extent B+树索引结点下一个ext4_extent_idx结构
	ix++;
    /*这个while循环保证从ext4 extent B+上层索引节点依次向下搜索，找到索引节点第一个ext4_extent_idx结构，再找到ext4_extent_idx结构
    对应的物理块地址block，从该block读取4K数据，这是ext4 extent B+树下一级索引节点。再通过这个索引节点第一个ext4_extent_idx结构找到
    下一个*/
    //ix这个ext4 extent B+索引节点逻辑块地址映射的物理块地址，这个磁盘的物理块地址保存了ix这个ext4 extent B+索引节点的4K数据，
    //ix物理块地址block的4K数据=ext4 extent B+索引节点ext4_extent_header头结点+N个ext4_extent_idx结构
	block = ext4_idx_pblock(ix);
	while (++depth < path->p_depth) {//这个while循环保证退出时，ix指向ext4 extent B+树最下层的索引结点
        //ix这个ext4 extent B+索引节点映射的物理块地址对应的bh
		bh = sb_bread(inode->i_sb, block);
		if (bh == NULL)
			return -EIO;
        //eh指向bh内存首地址，该bh的4K是ix这个ext4 extent B+索引节点的4K数据，ext4_extent_header头结点+N个ext4_extent_idx结构，总大小是4K
		eh = ext_block_hdr(bh);
		/* subtract from p_depth to get proper eh_depth */
		if (ext4_ext_check_block(inode, eh,
					 path->p_depth - depth, bh)) {
			put_bh(bh);
			return -EIO;
		}
        //ix这个ext4_extent B+树索引节点第一个ext4_extent_idx结构
		ix = EXT_FIRST_INDEX(eh);
        //ix这个ext4_extent B+树索引节点第一个ext4_extent_idx结构映射的物理块地址
		block = ext4_idx_pblock(ix);
		put_bh(bh);
	}
    //运行到这里，block是ext4_extent B+树最下层索引节点第一个ext4_extent_idx结构对应的物理块地址。这4K大小的物理块保存是
    //ext4_extent B+树的叶子节点，详细点是 block物理块4K数据=ext4_extent B+树叶子节点头结点ext4_extent_header + N个ext4_extent结构
	bh = sb_bread(inode->i_sb, block);
	if (bh == NULL)
		return -EIO;
    //eh内存是ext4_extent B+树最底层的叶子结点
	eh = ext_block_hdr(bh);
	if (ext4_ext_check_block(inode, eh, path->p_depth - depth, bh)) {
		put_bh(bh);
		return -EIO;
	}
    //ext4_extent B+树叶子节点第一个ext4_extent结构
	ex = EXT_FIRST_EXTENT(eh);
found_extent:
    //最后logical记录的是ext4_extent B+树最靠左的索引节点下的叶子节点的第一个ext4_extent结构的逻辑块地址
	*logical = le32_to_cpu(ex->ee_block);
    //逻辑块地址对应的物理块地址
	*phys = ext4_ext_pblock(ex);
	*ret_ex = ex;
	if (bh)
		put_bh(bh);
	return 0;
}

/*
 * ext4_ext_next_allocated_block:
 * returns allocated block in subsequent extent or EXT_MAX_BLOCKS.
 * NOTE: it considers block number from index entry as
 * allocated block. Thus, index entries have to be consistent
 * with leaves.
 */
static ext4_lblk_t
ext4_ext_next_allocated_block(struct ext4_ext_path *path)
{
	int depth;

	BUG_ON(path == NULL);
	depth = path->p_depth;

	if (depth == 0 && path->p_ext == NULL)
		return EXT_MAX_BLOCKS;

	while (depth >= 0) {
		if (depth == path->p_depth) {
			/* leaf */
			if (path[depth].p_ext &&
				path[depth].p_ext !=
					EXT_LAST_EXTENT(path[depth].p_hdr))
			  return le32_to_cpu(path[depth].p_ext[1].ee_block);
		} else {
			/* index */
			if (path[depth].p_idx !=
					EXT_LAST_INDEX(path[depth].p_hdr))
			  return le32_to_cpu(path[depth].p_idx[1].ei_block);
		}
		depth--;
	}

	return EXT_MAX_BLOCKS;
}

/*
 * ext4_ext_next_leaf_block:
 * returns first allocated block from next leaf or EXT_MAX_BLOCKS
 */
/**/
//回到ext4 extent B+树上层的索引节点，找到path[depth].p_idx指向的ext4_extent_idx，
//这个索引节点结构ext4_extent_idx的起始逻辑块地址最接近传入的逻辑块地址map->m_lblk，
//接着找到紧挨着这个ext4_extent_idx结构后边的ext4_extent_idx，这个ext4_extent_idx的起始
//逻辑块地址就可能大于要插入ext4 extent B+树的ext4_extent，该ext4_extent就插入该它下边
//的叶子节点最后返回新的ext4_extent_idx的起始逻辑块地址。如果找不到返回EXT_MAX_BLOCKS
static ext4_lblk_t ext4_ext_next_leaf_block(struct ext4_ext_path *path)
{
	int depth;

	BUG_ON(path == NULL);
	depth = path->p_depth;

  /*执行到这里，说明原来的叶子节点所有ext4_extent逻辑块地址范围太小，要插入ext4 extent B+树
  的新ext4_extent起始逻辑块地址太大。然后在该函数，要从B+树叶子节点回到上一层的索引
  节点，找到path[depth].p_idx指向的ext4_extent_idx。这个ext4_extent_idx在
  ext4_ext_find_extent->ext4_ext_binsearch_idx()中找到并赋值，具体是从ext4 extent B+树
  从上层到下层，依次在每一层索引节点中查找哪个ext4_extent_idx起始逻辑块地址最接近
  传入的要查找逻辑块地址block，然后path[depth].p_idx=ext4_extent_idx。这个函数是在
  要插入ext4 extent B+树的ext4_extent起始逻辑块地址大于原来的叶子节点所有ext4_extent
  逻辑块地址时，回到B+树索引节点，找到上一层索引节点path[depth].p_idx指向的
  ext4_extent_idx，原来的叶子节点正是在这个索引节点下。最后返回path[depth].p_idx指向的
  ext4_extent_idx的后边的ext4_extent_idx。后续就要在这个ext4_extent_idx生根发芽，要插入
  ext4 extent B+树的ext4_extent就是要插入这个ext4_extent_idx。为什么要这样操作，因为
  最初 要插入ext4 extent B+树的ext4_extent是要插入path[depth].p_idx指向的索引节点
  ext4_extent_idx下的叶子节点，但是要插入的ext4_extent的起始逻辑块地址这个叶子节点
  所有ext4_extent结构的起始逻辑块地址。那肯定要找个起始逻辑块地址更大的索引节点
  ext4_extent_idx，然后要插入ext4 extent B+树的ext4_extent会尝试插入到这个
ext4_extent_idx下的叶子节点。于是就找到path[depth].p_idx指向的索引节点ext4_extent_idx后的
  ext4_extent_idx，这就是本函数最终找到的ext4_extent_idx。ext4 extent B+树索引节点
  的是一个个ext4_extent_idx从左到右组成的，从左到右，每个ext4_extent_idx的逻辑块
  起始地址依次增大。这里有个问题，万一新找到的ext4_extent_idx起始逻辑块地址还是太小咋办?
  */
	if (depth == 0)//没有叶子节点
        /* zero-tree has no leaf blocks at all */
		return EXT_MAX_BLOCKS;

	/* go to index block */
	depth--;//depth--就到ext4_extent B+树的索引节点层了

	while (depth >= 0) {
        //path[depth].p_idx指向起始逻辑块地址最接近传入的起始逻辑块地址map->m_lblk的
        //ext4_extent_idx，EXT_LAST_INDEX(path[depth].p_hdr)是ext4 extent B+树索引节点
        //最后一个ext4_extent_idx。二者不能相等，因为这里是return path[depth].p_idx后边
        //的ext4_extent_idx即path[depth].p_idx[1].ei_block。path[depth].p_idx如果是索引
        //节点随后一个ext4_extent_idx，还怎么return它后边的ext4_extent_idx。
		if (path[depth].p_idx != EXT_LAST_INDEX(path[depth].p_hdr))
			return (ext4_lblk_t) le32_to_cpu(path[depth].p_idx[1].ei_block);
        
		depth--;//减1到上一层的ext4 extent B+树索引节点
	}

	return EXT_MAX_BLOCKS;
}

/*
 * ext4_ext_correct_indexes:
 * if leaf gets modified and modified extent is first in the leaf,
 * then we have to correct all indexes above.
 * TODO: do we need to correct tree in all cases?
 */
//看着是修改ext4 extent B+树索引节点的数据，因为叶子节点有更新了
static int ext4_ext_correct_indexes(handle_t *handle, struct inode *inode,
				struct ext4_ext_path *path)
{
	struct ext4_extent_header *eh;
	int depth = ext_depth(inode);
	struct ext4_extent *ex;
	__le32 border;
	int k, err = 0;

	eh = path[depth].p_hdr;
	ex = path[depth].p_ext;

	if (unlikely(ex == NULL || eh == NULL)) {
		EXT4_ERROR_INODE(inode,
				 "ex %p == NULL or eh %p == NULL", ex, eh);
		return -EIO;
	}

	if (depth == 0) {
		/* there is no tree at all */
		return 0;
	}

	if (ex != EXT_FIRST_EXTENT(eh)) {
		/* we correct tree if first leaf got modified only */
		return 0;
	}

	/*
	 * TODO: we need correction if border is smaller than current one
	 */
	k = depth - 1;
	border = path[depth].p_ext->ee_block;
	err = ext4_ext_get_access(handle, inode, path + k);
	if (err)
		return err;
	path[k].p_idx->ei_block = border;
	err = ext4_ext_dirty(handle, inode, path + k);
	if (err)
		return err;

	while (k--) {
		/* change all left-side indexes */
		if (path[k+1].p_idx != EXT_FIRST_INDEX(path[k+1].p_hdr))
			break;
		err = ext4_ext_get_access(handle, inode, path + k);
		if (err)
			break;
		path[k].p_idx->ei_block = border;
		err = ext4_ext_dirty(handle, inode, path + k);
		if (err)
			break;
	}

	return err;
}
//测试ex1和它后边的ex2这两个ext4_extent的逻辑块和物理块地址是否紧挨着，是则ex1可以合并到ex2并返回1。不能合并发乎0
int
ext4_can_extents_be_merged(struct inode *inode, struct ext4_extent *ex1,
				struct ext4_extent *ex2)
{
	unsigned short ext1_ee_len, ext2_ee_len, max_len;

	/*
	 * Make sure that both extents are initialized. We don't merge
	 * uninitialized extents so that we can be sure that end_io code has
	 * the extent that was written properly split out and conversion to
	 * initialized is trivial.
	 */
	//参与合并的两个ext4_extent必须是initialized状态，否则无法合并
	if (ext4_ext_is_uninitialized(ex1) || ext4_ext_is_uninitialized(ex2))
		return 0;

	if (ext4_ext_is_uninitialized(ex1))
		max_len = EXT_UNINIT_MAX_LEN;
	else
		max_len = EXT_INIT_MAX_LEN;//ext4_extent最大逻辑块个数max_len是0x8000

	ext1_ee_len = ext4_ext_get_actual_len(ex1);
	ext2_ee_len = ext4_ext_get_actual_len(ex2);

    //ex1的逻辑块结束地址必须紧挨着ex2逻辑块起始地址
	if (le32_to_cpu(ex1->ee_block) + ext1_ee_len !=
			le32_to_cpu(ex2->ee_block))
		return 0;

	/*
	 * To allow future support for preallocated extents to be added
	 * as an RO_COMPAT feature, refuse to merge to extents if
	 * this can result in the top bit of ee_len being set.
	 */
	//ex1和ex2的逻辑块个数之和不能超过max_len，因为ext4_extent最大逻辑块个数max_len，0x8000
	if (ext1_ee_len + ext2_ee_len > max_len)
		return 0;
#ifdef AGGRESSIVE_TEST
	if (ext1_ee_len >= 4)
		return 0;
#endif
    //ex1的物理块结束地址必须紧挨着ex2物理块起始地址
	if (ext4_ext_pblock(ex1) + ext1_ee_len == ext4_ext_pblock(ex2))
		return 1;
	return 0;
}

/*
 * This function tries to merge the "ex" extent to the next extent in the tree.
 * It always tries to merge towards right. If you want to merge towards
 * left, pass "ex - 1" as argument instead of "ex".
 * Returns 0 if the extents (ex and ex+1) were _not_ merged and returns
 * 1 if they got merged.
 */
//尝试把ex后边的ex+1、ex+2 ....这些ext4_extent的逻辑块和物理块地址循环合并到ex，当然合并
//的前提是两个ext4_extent的逻辑块地址和物理块地址前后紧挨着
static int ext4_ext_try_to_merge_right(struct inode *inode,
				 struct ext4_ext_path *path,
				 struct ext4_extent *ex)
{
	struct ext4_extent_header *eh;
	unsigned int depth, len;
	int merge_done = 0;
	int uninitialized = 0;

	depth = ext_depth(inode);
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

    //ex不能是ext4_extent B+树叶子节点中最后一个ext4_extent结构，否则还咋合并
	while (ex < EXT_LAST_EXTENT(eh)) {
        //测试ex1和它后边的ex + 1这两个ext4_extent的逻辑块和物理块地址是否紧挨着，是ex1则可以合并到ex2并返回1。不能合并返回0
		if (!ext4_can_extents_be_merged(inode, ex, ex + 1))
			break;
		/* merge with next extent! */
		if (ext4_ext_is_uninitialized(ex))
			uninitialized = 1;
        //ex->ee_len重新赋值为ex和ex+1这两个ext4_extent的逻辑块数之和
		ex->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex)
				+ ext4_ext_get_actual_len(ex + 1));
		if (uninitialized)
			ext4_ext_mark_uninitialized(ex);

        //ex+1不是最后一个ext4_extent结构
		if (ex + 1 < EXT_LAST_EXTENT(eh)) {
            //len是ex+1这个ext4_extent结构体的长度
			len = (EXT_LAST_EXTENT(eh) - ex - 1)
				* sizeof(struct ext4_extent);
            //把ex+1这个ext4_extent结构体的内容复制到ex+2，这样不是会把ex+2的内容覆盖了
            //，为什么要这样操作?????
			memmove(ex + 1, ex + 2, len);
		}
        //ext4 extent B+树extent树减1
		le16_add_cpu(&eh->eh_entries, -1);
		merge_done = 1;//置1表示合并成功
		WARN_ON(eh->eh_entries == 0);
		if (!eh->eh_entries)
			EXT4_ERROR_INODE(inode, "eh->eh_entries = 0!");
	}

	return merge_done;
}

/*
 * This function does a very simple check to see if we can collapse
 * an extent tree with a single extent tree leaf block into the inode.
 */
//如果ext4_extent B+树深度是1，并且叶子结点有很少的ext4_extent结构，则把叶子结点的ext4_extent结构复制到root节点，
//并把原来保存叶子节点ext4_extent结构等数据的物理块释放会ext4文件系统，节省空间
static void ext4_ext_try_to_merge_up(handle_t *handle,
				     struct inode *inode,
				     struct ext4_ext_path *path)
{
	size_t s;
    //计算ext4_extent B+的root节点能容纳多少个ext4_extent结构给max_root
	unsigned max_root = ext4_ext_space_root(inode, 0);
	ext4_fsblk_t blk;

    //ext4_extent B+树深度必须是1，即root索引节点+叶子结点。并且，root节点的entry数必须是1，即只能有一个叶子结点。并且叶子结点
    //的ext4_extent数不能大于max_root个。以上条件有一个不成立，直接return。
	if ((path[0].p_depth != 1) ||
	    (le16_to_cpu(path[0].p_hdr->eh_entries) != 1) ||
	    (le16_to_cpu(path[1].p_hdr->eh_entries) > max_root))
		return;

	/*
	 * We need to modify the block allocation bitmap and the block
	 * group descriptor to release the extent tree block.  If we
	 * can't get the journal credits, give up.
	 */
	if (ext4_journal_extend(handle, 2))
		return;

	/*
	 * Copy the extent data up to the inode
	 */
	//root节点索引节点保存的物理块号，这4K大小物理块保存了叶子结点的ext4_extent等数据
	blk = ext4_idx_pblock(path[0].p_idx);
    //叶子节点的ext4_extent结构个数对应的字节空间给s
	s = le16_to_cpu(path[1].p_hdr->eh_entries) *
		sizeof(struct ext4_extent_idx);
	s += sizeof(struct ext4_extent_header);//再加上叶子结点的头结点字节空间

    //下边这是把叶子节点的ext4_extent结构等数据复制到root 节点内存
	memcpy(path[0].p_hdr, path[1].p_hdr, s);
	path[0].p_depth = 0;//ext4_extent B+树root节点深度清0
	//EXT_FIRST_EXTENT(path[0].p_hdr)是root节点第一个ext4_extent结构的内存地址，(path[1].p_ext - EXT_FIRST_EXTENT(path[1].p_hdr))
	//是计算原来叶子节点中，path[1].p_ext指向的ext4_extent结构内存地址与第一个ext4_extent结构内存地址之前的差值，
	//EXT_FIRST_EXTENT(path[0].p_hdr)加上这个差值，就是path[0].p_ext指向的ext4_extent的内存地址
	path[0].p_ext = EXT_FIRST_EXTENT(path[0].p_hdr) +
		(path[1].p_ext - EXT_FIRST_EXTENT(path[1].p_hdr));
    //root节点这个新的叶子结点的最大能保存的ext4_extent结构个数
	path[0].p_hdr->eh_max = cpu_to_le16(max_root);

    //把原来保存叶子节点的ext4_extent等数据的物理块释放会ext4文件系统
	brelse(path[1].p_bh);
	ext4_free_blocks(handle, inode, NULL, blk, 1,
			 EXT4_FREE_BLOCKS_METADATA | EXT4_FREE_BLOCKS_FORGET |
			 EXT4_FREE_BLOCKS_RESERVE);
}

/*
 * This function tries to merge the @ex extent to neighbours in the tree.
 * return 1 if merge left else 0.
 */
//尝试把ex后的ext4_extent结构的逻辑块和物理块地址合并到ex。兵器，如果ext4_extent B+树深度是1，并且叶子结点有很少的ext4_extent结构，
//则尝试把叶子结点的ext4_extent结构移动到root节点
static void ext4_ext_try_to_merge(handle_t *handle,
				  struct inode *inode,
				  struct ext4_ext_path *path,
				  struct ext4_extent *ex) {
	struct ext4_extent_header *eh;
	unsigned int depth;
	int merge_done = 0;

	depth = ext_depth(inode);
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

	if (ex > EXT_FIRST_EXTENT(eh))
        //尝试把(ex-1)后边的ex、ex+1 ....这些ext4_extent循环合并到ex-1,有一次合并则返回1
		merge_done = ext4_ext_try_to_merge_right(inode, path, ex - 1);

	if (!merge_done)
        //上边没有发生ext4_extent合并，这里则尝试把ex后边的ex+1、ex+2 ....这些ext4_extent循环合并到ex
		(void) ext4_ext_try_to_merge_right(inode, path, ex);
    
    //如果ext4_extent B+树深度是1，并且叶子结点有很少的ext4_extent结构，则把叶子结点的ext4_extent结构移动到root节点，
    //并把原来保存叶子节点ext4_extent结构等数据的物理块释放会ext4文件系统，节省空间
	ext4_ext_try_to_merge_up(handle, inode, path);
}

/*
 * check if a portion of the "newext" extent overlaps with an
 * existing extent.
 *
 * If there is an overlap discovered, it updates the length of the newext
 * such that there will be no overlap, and then returns 1.
 * If there is no overlap found, it returns 0.
 */
static unsigned int ext4_ext_check_overlap(struct ext4_sb_info *sbi,
					   struct inode *inode,
					   struct ext4_extent *newext,
					   struct ext4_ext_path *path)
{
	ext4_lblk_t b1, b2;
	unsigned int depth, len1;
	unsigned int ret = 0;

	b1 = le32_to_cpu(newext->ee_block);
	len1 = ext4_ext_get_actual_len(newext);
	depth = ext_depth(inode);
	if (!path[depth].p_ext)
		goto out;
	b2 = EXT4_LBLK_CMASK(sbi, le32_to_cpu(path[depth].p_ext->ee_block));

	/*
	 * get the next allocated block if the extent in the path
	 * is before the requested block(s)
	 */
	if (b2 < b1) {
		b2 = ext4_ext_next_allocated_block(path);
		if (b2 == EXT_MAX_BLOCKS)
			goto out;
		b2 = EXT4_LBLK_CMASK(sbi, b2);
	}

	/* check for wrap through zero on extent logical start block*/
	if (b1 + len1 < b1) {
		len1 = EXT_MAX_BLOCKS - b1;
		newext->ee_len = cpu_to_le16(len1);
		ret = 1;
	}

	/* check for overlap */
	if (b1 + len1 > b2) {
		newext->ee_len = cpu_to_le16(b2 - b1);
		ret = 1;
	}
out:
	return ret;
}

/*
 * ext4_ext_insert_extent:
 * tries to merge requsted extent into the existing extent or
 * inserts requested extent as new one into the tree,
 * creating new leaf in the no-space case.
 */
//ext4_ext_map_blocks()->ext4_ext_handle_uninitialized_extents()/ext4_ext_handle_unwritten_extents()->
//ext4_ext_convert_to_initialized()->ext4_split_extent()->ext4_split_extent_at()->ext4_ext_insert_extent()

/*什么实际会执行ext4_ext_insert_extent()函数?两种情况，情况1:ext4_ext_map_blocks()为map在ext4 extent B+树找不到逻辑块地址接近的
ext4_extent结构，则为map分配一个新的ext4_extent结构，然后执行ext4_ext_insert_extent()把这个新的ext4_extent结构插入ext4 extent B+树。
情况2:在ext4_split_extent_at()中，把path[depth].p_ext指向的ext4_extent结构(即ex)的逻辑块范围分割成两段，把后半段逻辑块范围对应的
ext4_extent结构执行ext4_ext_insert_extent()插入ext4 extent B+树。
*/
int ext4_ext_insert_extent(handle_t *handle, struct inode *inode,
				struct ext4_ext_path *path,
				struct ext4_extent *newext, int flag)//newext是要插入extent B+数的ext4_extent
{
	struct ext4_extent_header *eh;
	struct ext4_extent *ex, *fex;
	struct ext4_extent *nearex; /* nearest extent */
	struct ext4_ext_path *npath = NULL;
	int depth, len, err;
	ext4_lblk_t next;
	unsigned uninitialized = 0;
	int flags = 0;

	if (unlikely(ext4_ext_get_actual_len(newext) == 0)) {
		EXT4_ERROR_INODE(inode, "ext4_ext_get_actual_len(newext) == 0");
		return -EIO;
	}
	depth = ext_depth(inode);
    //ext4 extent B+树叶子节点，指向起始逻辑块地址最接近map->m_lblk这个起始逻辑块地址的ext4_extent
	ex = path[depth].p_ext;
	eh = path[depth].p_hdr;
	if (unlikely(path[depth].p_hdr == NULL)) {
		EXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
		return -EIO;
	}

    /*下边这个if (ex && !(flag & EXT4_GET_BLOCKS_PRE_IO))判断，是判断newex跟ex、ex前边的ext4_extent结构、ex后边的ext4_extent结构
     逻辑块地址范围是否紧挨着，是的话才能将二者合并。但!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
     能合并还要符合一个苛刻条件:参与合并的两个ext4_extent必须是initialized状态，否则无法合并*/
    
	/* try to insert block into found extent and return */
	if (ex && !(flag & EXT4_GET_BLOCKS_PRE_IO)) {//if成立

		/*
		 * Try to see whether we should rather test the extent on
		 * right from ex, or from the left of ex. This is because
		 * ext4_ext_find_extent() can return either extent on the
		 * left, or on the right from the searched position. This
		 * will make merging more effective.
		 */
		//newext在要插入的ex逻辑地址范围后边，这样newex无法插入ex，只能想办法插入到ex后边的那个ext4_extent结构
		if (ex < EXT_LAST_EXTENT(eh) &&
		    (le32_to_cpu(ex->ee_block) +
		    ext4_ext_get_actual_len(ex) <
		    le32_to_cpu(newext->ee_block))) {
			ex += 1;//ex++  指向后边的ext4_extent结构
			goto prepend;
        //newext在要插入的ex逻辑地址范围前边，这样newex无法插入ex，只能想办法插入到ex前边的那个ext4_extent结构
		} else if ((ex > EXT_FIRST_EXTENT(eh)) &&
			   (le32_to_cpu(newext->ee_block) +
			   ext4_ext_get_actual_len(newext) <
			   le32_to_cpu(ex->ee_block)))
			ex -= 1;

        //到这里，有可能上边的两个if都不成立，ex += 1 和 ex -= 1都没执行，ex还是path[depth].p_ext那个ext4_extent结构
		/* Try to append newex to the ex */
        //测试ex和它后边的newext这两个ext4_extent的逻辑块和物理块地址是否紧挨着，是则合并二者逻辑块地址并返回1
        /*参与合并的两个ext4_extent必须是initialized状态，否则无法合并*/
		if (ext4_can_extents_be_merged(inode, ex, newext)) {
			ext_debug("append [%d]%d block to %u:[%d]%d"
				  "(from %llu)\n",
				  ext4_ext_is_uninitialized(newext),
				  ext4_ext_get_actual_len(newext),
				  le32_to_cpu(ex->ee_block),
				  ext4_ext_is_uninitialized(ex),
				  ext4_ext_get_actual_len(ex),
				  ext4_ext_pblock(ex));
			err = ext4_ext_get_access(handle, inode,
						  path + depth);
			if (err)
				return err;

			/*
			 * ext4_can_extents_be_merged should have checked
			 * that either both extents are uninitialized, or
			 * both aren't. Thus we need to check only one of
			 * them here.
			 */
			//ex没有初始化过则uninitialized = 1
			if (ext4_ext_is_uninitialized(ex))
				uninitialized = 1;
            //把newext的逻辑块地址范围合并到ex
			ex->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex)
					+ ext4_ext_get_actual_len(newext));
			if (uninitialized)
				ext4_ext_mark_uninitialized(ex);//标记ex未初始化
			eh = path[depth].p_hdr;
            
			nearex = ex;//nearex是ex
			
			goto merge;//跳转到merge分支
		}

prepend:
		/* Try to prepend newex to the ex */
        //测试newext和它后边的ex这两个ext4_extent的逻辑块和物理块地址是否紧挨着，是则合并二者逻辑块地址并返回1
        /*参与合并的两个ext4_extent必须是initialized状态，否则无法合并*/
		if (ext4_can_extents_be_merged(inode, newext, ex)) {
			ext_debug("prepend %u[%d]%d block to %u:[%d]%d"
				  "(from %llu)\n",
				  le32_to_cpu(newext->ee_block),
				  ext4_ext_is_uninitialized(newext),
				  ext4_ext_get_actual_len(newext),
				  le32_to_cpu(ex->ee_block),
				  ext4_ext_is_uninitialized(ex),
				  ext4_ext_get_actual_len(ex),
				  ext4_ext_pblock(ex));
			err = ext4_ext_get_access(handle, inode,
						  path + depth);
			if (err)
				return err;

			/*
			 * ext4_can_extents_be_merged should have checked
			 * that either both extents are uninitialized, or
			 * both aren't. Thus we need to check only one of
			 * them here.
			 */
			//ex没有初始化过则uninitialized = 1
			if (ext4_ext_is_uninitialized(ex))
				uninitialized = 1;
            //把ex的逻辑块地址范围合并到newext，但最终还是以ex
			ex->ee_block = newext->ee_block;
            //更新ex的起始物理块地址为newext的逻辑块地址
			ext4_ext_store_pblock(ex, ext4_ext_pblock(newext));
            //ex->ee_len和ex和newext的逻辑块个数之和
			ex->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex)
					+ ext4_ext_get_actual_len(newext));
			if (uninitialized)
				ext4_ext_mark_uninitialized(ex);
			eh = path[depth].p_hdr;
            
			nearex = ex;//nearex是ex
			
			goto merge;//跳转到merge分支
		}
	}

    /*走到这里，说明ex和newex没有发生合并，*/
    
	depth = ext_depth(inode);
	eh = path[depth].p_hdr;
    //eh->eh_max是ext4_extent B+树叶子节点最大ext4_extent个数，没有超过则跳到has_space分支
	if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max))
		goto has_space;

    /*到这里说明ext4_extent B+叶子节点空间不够了，需要扩容*/
    
	/* probably next leaf has space for us? */
    //ext4 extent B+树叶子节点最后一个ext4_extent结构
	fex = EXT_LAST_EXTENT(eh);
	next = EXT_MAX_BLOCKS;//0x8000-1

    //如果要插入的newext起始逻辑块地址大于ext4 extent B+树叶子节点最后一个ext4_extent
    //结构的，说明超出ext4 extent B+树叶子节点所有ext4_extent结构的逻辑块范围了
	if (le32_to_cpu(newext->ee_block) > le32_to_cpu(fex->ee_block))
//回到ext4 extent B+树叶子节点上层的索引节点，找到path[depth].p_idx指向的ext4_extent_idx，
//这个索引节点结构ext4_extent_idx的起始逻辑块地址最接近传入的逻辑块地址map->m_lblk，
//接着找到紧挨着这个ext4_extent_idx结构后边的ext4_extent_idx，这个ext4_extent_idx的起始
//逻辑块地址就可能大于本次要插入ext4 extent B+树的ext4_extent，即newext。该ext4_extent就插入新找到的索引节点ext4_extent_idx的下边
//的叶子节点，最后返回新的ext4_extent_idx的起始逻辑块地址。如果找不到这个索引节点ext4_extent_idx，返回EXT_MAX_BLOCKS
		next = ext4_ext_next_leaf_block(path);
    
	if (next != EXT_MAX_BLOCKS) {//成立说明找到了合适的ext4_extent_idx
		ext_debug("next leaf block - %u\n", next);
		BUG_ON(npath != NULL);
        //next是ext4 extent B+树新找到的索引节点ext4_extent_idx的起始逻辑块地址，这个逻辑块地址更大，本次要插入的newext的逻辑块地址
        //在这个ext4_extent_idx的逻辑块地址范围内。下边是根据next这个逻辑地址，在ext4 extent B+树，从上层到下层，一层层找到
        //起始逻辑块地址最接近next的索引节点ext4_extent_idx结构和叶子节点ext4_extent结构，保存到npath[]
		npath = ext4_ext_find_extent(inode, next, NULL);
		if (IS_ERR(npath))
			return PTR_ERR(npath);
		BUG_ON(npath->p_depth != path->p_depth);
        //按照next这个逻辑块地址找到的新的叶子节点的ext4_extent_header结构
		eh = npath[depth].p_hdr;
        //叶子节点的ext4_extent树没有超过eh->eh_max
		if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max)) {
			ext_debug("next leaf isn't full(%d)\n",
				  le16_to_cpu(eh->eh_entries));
            //path指向按照next这个逻辑块地址找到的struct ext4_ext_path
			path = npath;
            //跳到has_space分支，把newext插入到按照next这个逻辑块地址找到的叶子节点
			goto has_space;
		}
		ext_debug("next leaf has no free space(%d,%d)\n",
			  le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));
	}

/*走到这里，1:说明前边ext4_ext_next_leaf_block()没有找到合适的ext4 extent B+树索引节点
ext4_extent_idx，即要插入的newext起始逻辑地址太大了，ext4 extent B+树索引节点的起始逻辑
块范围太小，newext无法插入。2:ext4 extent B+树叶子结点的ext4_extent结构满了，没有空间了，需要增大树层数

还有一种情况可能要考虑，ext4 extent B+树是空的!在刚读写文件时，B+树层数是0或者1，此时叶子结点ext4_extent结构很容易就满了，
需要按照这个场景分析一下ext4_ext_insert_extent()函数的执行流程*/

	/*
	 * There is no free space in the found leaf.
	 * We're gonna add a new leaf in the tree.
	 */
	if (flag & EXT4_GET_BLOCKS_METADATA_NOFAIL)
		flags = EXT4_MB_USE_RESERVED;
	err = ext4_ext_create_new_leaf(handle, inode, flags, path, newext);
	if (err)
		goto cleanup;
	depth = ext_depth(inode);
	eh = path[depth].p_hdr;

/*到这里，path[depth].p_ext所在叶子节点肯定有空闲entry，即空闲的ext4_extent结构，直接把newext插入到叶子节点某个ext4_extent位置处*/
has_space:
    //nearex指向起始逻辑块地址最接近map->m_lblk这个起始逻辑块地址的ext4_extent
	nearex = path[depth].p_ext;

	err = ext4_ext_get_access(handle, inode, path + depth);
	if (err)
		goto cleanup;

	if (!nearex) {//ext4 extent B+树叶子节点没有extent结构，可能吗?
		/* there is no extent in this leaf, create first one */
		ext_debug("first extent in the leaf: %u:%llu:[%d]%d\n",
				le32_to_cpu(newext->ee_block),
				ext4_ext_pblock(newext),
				ext4_ext_is_uninitialized(newext),
				ext4_ext_get_actual_len(newext));
        //nearex指向ext4 extent B+树叶子节点第一个ext4_extent结构内存地址，此时没有ext4_extent结构
		nearex = EXT_FIRST_EXTENT(eh);
	} else {
	    //newext的起始逻辑块地址在nearex后边
		if (le32_to_cpu(newext->ee_block)
			   > le32_to_cpu(nearex->ee_block)) {
			/* Insert after */
			ext_debug("insert %u:%llu:[%d]%d before: "
					"nearest %p\n",
					le32_to_cpu(newext->ee_block),
					ext4_ext_pblock(newext),
					ext4_ext_is_uninitialized(newext),
					ext4_ext_get_actual_len(newext),
					nearex);
			nearex++;//nearex++指向后边的一个ext4_extent结构
		} else {
			/* Insert before */
			BUG_ON(newext->ee_block == nearex->ee_block);
			ext_debug("insert %u:%llu:[%d]%d after: "
					"nearest %p\n",
					le32_to_cpu(newext->ee_block),
					ext4_ext_pblock(newext),
					ext4_ext_is_uninitialized(newext),
					ext4_ext_get_actual_len(newext),
					nearex);
		}
        //这是计算nearex这个ext4_extent结构到叶子节点最后一个ext4_extent结构之间的
        //ext4_extent结构个数???
		len = EXT_LAST_EXTENT(eh) - nearex + 1;
		if (len > 0) {
			ext_debug("insert %u:%llu:[%d]%d: "
					"move %d extents from 0x%p to 0x%p\n",
					le32_to_cpu(newext->ee_block),
					ext4_ext_pblock(newext),
					ext4_ext_is_uninitialized(newext),
					ext4_ext_get_actual_len(newext),
					len, nearex, nearex + 1);
            //这是把nearex这个ext4_extent结构 ~ 最后一个ext4_extent结构之间的所有
            //ext4_extent结构的数据整体向后移动一个ext4_extent结构大小，腾出原来
            //nearex这个ext4_extent结构的空间，下边看着是用newext来填充
			memmove(nearex + 1, nearex,
				len * sizeof(struct ext4_extent));
		}
	}

    /*下边是把newext的逻辑块起始地址、物理块起始地址、映射的物理块个数等信息赋值
    给nearex，相当于把newext添加到ext4 extent B+树叶子节点原来nearex的位置。然后叶子节点
    ext4_extent个数加1。path[depth].p_ext指向newext*/
	le16_add_cpu(&eh->eh_entries, 1);//ext4 extent B+树叶子节点ext4_extent个数加1
	path[depth].p_ext = nearex;//相当于path[depth].p_ext指向newext
	
    //nearex->ee_block赋值为newext起始逻辑块地址
	nearex->ee_block = newext->ee_block;
    //用newext起始物理块地址赋值给nearex
	ext4_ext_store_pblock(nearex, ext4_ext_pblock(newext));
	nearex->ee_len = newext->ee_len;//nearex->ee_len赋值为newext的

/*到这里后，newext要么已经合并到了ex，要么已经插入ext4 extent B+树，下边的没啥重要操作*/
merge:
	/* try to merge extents */
	if (!(flag & EXT4_GET_BLOCKS_PRE_IO))
      //尝试把ex后的ext4_extent结构的逻辑块和物理块地址合并到ex。兵器，如果ext4_extent B+树深度是1，并且叶子结点有很少的ext4_extent结构，
      //则尝试把叶子结点的ext4_extent结构移动到root节点
		ext4_ext_try_to_merge(handle, inode, path, nearex);


	/* time to correct all indexes above */
    //看着是修改ext4 extent B+树索引节点的数据，因为叶子节点有更新了
	err = ext4_ext_correct_indexes(handle, inode, path);
	if (err)
		goto cleanup;

	err = ext4_ext_dirty(handle, inode, path + path->p_depth);

cleanup:
	if (npath) {
		ext4_ext_drop_refs(npath);
		kfree(npath);
	}
	return err;
}

static int ext4_fill_fiemap_extents(struct inode *inode,
				    ext4_lblk_t block, ext4_lblk_t num,
				    struct fiemap_extent_info *fieinfo)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent *ex;
	struct extent_status es;
	ext4_lblk_t next, next_del, start = 0, end = 0;
	ext4_lblk_t last = block + num;
	int exists, depth = 0, err = 0;
	unsigned int flags = 0;
	unsigned char blksize_bits = inode->i_sb->s_blocksize_bits;

	while (block < last && block != EXT_MAX_BLOCKS) {
		num = last - block;
		/* find extent for this block */
		down_read(&EXT4_I(inode)->i_data_sem);

		if (path && ext_depth(inode) != depth) {
			/* depth was changed. we have to realloc path */
			kfree(path);
			path = NULL;
		}

		path = ext4_ext_find_extent(inode, block, path);
		if (IS_ERR(path)) {
			up_read(&EXT4_I(inode)->i_data_sem);
			err = PTR_ERR(path);
			path = NULL;
			break;
		}

		depth = ext_depth(inode);
		if (unlikely(path[depth].p_hdr == NULL)) {
			up_read(&EXT4_I(inode)->i_data_sem);
			EXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
			err = -EIO;
			break;
		}
		ex = path[depth].p_ext;
		next = ext4_ext_next_allocated_block(path);
		ext4_ext_drop_refs(path);

		flags = 0;
		exists = 0;
		if (!ex) {
			/* there is no extent yet, so try to allocate
			 * all requested space */
			start = block;
			end = block + num;
		} else if (le32_to_cpu(ex->ee_block) > block) {
			/* need to allocate space before found extent */
			start = block;
			end = le32_to_cpu(ex->ee_block);
			if (block + num < end)
				end = block + num;
		} else if (block >= le32_to_cpu(ex->ee_block)
					+ ext4_ext_get_actual_len(ex)) {
			/* need to allocate space after found extent */
			start = block;
			end = block + num;
			if (end >= next)
				end = next;
		} else if (block >= le32_to_cpu(ex->ee_block)) {
			/*
			 * some part of requested space is covered
			 * by found extent
			 */
			start = block;
			end = le32_to_cpu(ex->ee_block)
				+ ext4_ext_get_actual_len(ex);
			if (block + num < end)
				end = block + num;
			exists = 1;
		} else {
			BUG();
		}
		BUG_ON(end <= start);

		if (!exists) {
			es.es_lblk = start;
			es.es_len = end - start;
			es.es_pblk = 0;
		} else {
			es.es_lblk = le32_to_cpu(ex->ee_block);
			es.es_len = ext4_ext_get_actual_len(ex);
			es.es_pblk = ext4_ext_pblock(ex);
			if (ext4_ext_is_uninitialized(ex))
				flags |= FIEMAP_EXTENT_UNWRITTEN;
		}

		/*
		 * Find delayed extent and update es accordingly. We call
		 * it even in !exists case to find out whether es is the
		 * last existing extent or not.
		 */
		next_del = ext4_find_delayed_extent(inode, &es);
		if (!exists && next_del) {
			exists = 1;
			flags |= FIEMAP_EXTENT_DELALLOC;
		}
		up_read(&EXT4_I(inode)->i_data_sem);

		if (unlikely(es.es_len == 0)) {
			EXT4_ERROR_INODE(inode, "es.es_len == 0");
			err = -EIO;
			break;
		}

		/*
		 * This is possible iff next == next_del == EXT_MAX_BLOCKS.
		 * we need to check next == EXT_MAX_BLOCKS because it is
		 * possible that an extent is with unwritten and delayed
		 * status due to when an extent is delayed allocated and
		 * is allocated by fallocate status tree will track both of
		 * them in a extent.
		 *
		 * So we could return a unwritten and delayed extent, and
		 * its block is equal to 'next'.
		 */
		if (next == next_del && next == EXT_MAX_BLOCKS) {
			flags |= FIEMAP_EXTENT_LAST;
			if (unlikely(next_del != EXT_MAX_BLOCKS ||
				     next != EXT_MAX_BLOCKS)) {
				EXT4_ERROR_INODE(inode,
						 "next extent == %u, next "
						 "delalloc extent = %u",
						 next, next_del);
				err = -EIO;
				break;
			}
		}

		if (exists) {
			err = fiemap_fill_next_extent(fieinfo,
				(__u64)es.es_lblk << blksize_bits,
				(__u64)es.es_pblk << blksize_bits,
				(__u64)es.es_len << blksize_bits,
				flags);
			if (err < 0)
				break;
			if (err == 1) {
				err = 0;
				break;
			}
		}

		block = es.es_lblk + es.es_len;
	}

	if (path) {
		ext4_ext_drop_refs(path);
		kfree(path);
	}

	return err;
}

/*
 * ext4_ext_put_gap_in_cache:
 * calculate boundaries of the gap that the requested block fits into
 * and cache this gap
 */
static void
ext4_ext_put_gap_in_cache(struct inode *inode, struct ext4_ext_path *path,
				ext4_lblk_t block)
{
	int depth = ext_depth(inode);
	unsigned long len;
	ext4_lblk_t lblock;
	struct ext4_extent *ex;

	ex = path[depth].p_ext;
	if (ex == NULL) {
		/*
		 * there is no extent yet, so gap is [0;-] and we
		 * don't cache it
		 */
		ext_debug("cache gap(whole file):");
	} else if (block < le32_to_cpu(ex->ee_block)) {
		lblock = block;
		len = le32_to_cpu(ex->ee_block) - block;
		ext_debug("cache gap(before): %u [%u:%u]",
				block,
				le32_to_cpu(ex->ee_block),
				 ext4_ext_get_actual_len(ex));
		if (!ext4_find_delalloc_range(inode, lblock, lblock + len - 1))
			ext4_es_insert_extent(inode, lblock, len, ~0,
					      EXTENT_STATUS_HOLE);
	} else if (block >= le32_to_cpu(ex->ee_block)
			+ ext4_ext_get_actual_len(ex)) {
		ext4_lblk_t next;
		lblock = le32_to_cpu(ex->ee_block)
			+ ext4_ext_get_actual_len(ex);

		next = ext4_ext_next_allocated_block(path);
		ext_debug("cache gap(after): [%u:%u] %u",
				le32_to_cpu(ex->ee_block),
				ext4_ext_get_actual_len(ex),
				block);
		BUG_ON(next == lblock);
		len = next - lblock;
		if (!ext4_find_delalloc_range(inode, lblock, lblock + len - 1))
			ext4_es_insert_extent(inode, lblock, len, ~0,
					      EXTENT_STATUS_HOLE);
	} else {
		lblock = len = 0;
		BUG();
	}

	ext_debug(" -> %u:%lu\n", lblock, len);
}

/*
 * ext4_ext_rm_idx:
 * removes index from the index block.
 */
static int ext4_ext_rm_idx(handle_t *handle, struct inode *inode,
			struct ext4_ext_path *path, int depth)
{
	int err;
	ext4_fsblk_t leaf;

	/* free index block */
	depth--;
	path = path + depth;
	leaf = ext4_idx_pblock(path->p_idx);
	if (unlikely(path->p_hdr->eh_entries == 0)) {
		EXT4_ERROR_INODE(inode, "path->p_hdr->eh_entries == 0");
		return -EIO;
	}
	err = ext4_ext_get_access(handle, inode, path);
	if (err)
		return err;

	if (path->p_idx != EXT_LAST_INDEX(path->p_hdr)) {
		int len = EXT_LAST_INDEX(path->p_hdr) - path->p_idx;
		len *= sizeof(struct ext4_extent_idx);
		memmove(path->p_idx, path->p_idx + 1, len);
	}

	le16_add_cpu(&path->p_hdr->eh_entries, -1);
	err = ext4_ext_dirty(handle, inode, path);
	if (err)
		return err;
	ext_debug("index is empty, remove it, free block %llu\n", leaf);
	trace_ext4_ext_rm_idx(inode, leaf);

	ext4_free_blocks(handle, inode, NULL, leaf, 1,
			 EXT4_FREE_BLOCKS_METADATA | EXT4_FREE_BLOCKS_FORGET);

	while (--depth >= 0) {
		if (path->p_idx != EXT_FIRST_INDEX(path->p_hdr))
			break;
		path--;
		err = ext4_ext_get_access(handle, inode, path);
		if (err)
			break;
		path->p_idx->ei_block = (path+1)->p_idx->ei_block;
		err = ext4_ext_dirty(handle, inode, path);
		if (err)
			break;
	}
	return err;
}

/*
 * ext4_ext_calc_credits_for_single_extent:
 * This routine returns max. credits that needed to insert an extent
 * to the extent tree.
 * When pass the actual path, the caller should calculate credits
 * under i_data_sem.
 */
int ext4_ext_calc_credits_for_single_extent(struct inode *inode, int nrblocks,
						struct ext4_ext_path *path)
{
	if (path) {
		int depth = ext_depth(inode);
		int ret = 0;

		/* probably there is space in leaf? */
		if (le16_to_cpu(path[depth].p_hdr->eh_entries)
				< le16_to_cpu(path[depth].p_hdr->eh_max)) {

			/*
			 *  There are some space in the leaf tree, no
			 *  need to account for leaf block credit
			 *
			 *  bitmaps and block group descriptor blocks
			 *  and other metadata blocks still need to be
			 *  accounted.
			 */
			/* 1 bitmap, 1 block group descriptor */
			ret = 2 + EXT4_META_TRANS_BLOCKS(inode->i_sb);
			return ret;
		}
	}

	return ext4_chunk_trans_blocks(inode, nrblocks);
}

/*
 * How many index/leaf blocks need to change/allocate to modify nrblocks?
 *
 * if nrblocks are fit in a single extent (chunk flag is 1), then
 * in the worse case, each tree level index/leaf need to be changed
 * if the tree split due to insert a new extent, then the old tree
 * index/leaf need to be updated too
 *
 * If the nrblocks are discontiguous, they could cause
 * the whole tree split more than once, but this is really rare.
 */
int ext4_ext_index_trans_blocks(struct inode *inode, int nrblocks, int chunk)
{
	int index;
	int depth;

	/* If we are converting the inline data, only one is needed here. */
	if (ext4_has_inline_data(inode))
		return 1;

	depth = ext_depth(inode);

	if (chunk)
		index = depth * 2;
	else
		index = depth * 3;

	return index;
}

static int ext4_remove_blocks(handle_t *handle, struct inode *inode,
			      struct ext4_extent *ex,
			      ext4_fsblk_t *partial_cluster,
			      ext4_lblk_t from, ext4_lblk_t to)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	unsigned short ee_len =  ext4_ext_get_actual_len(ex);
	ext4_fsblk_t pblk;
	int flags = 0;

	if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode))
		flags |= EXT4_FREE_BLOCKS_METADATA | EXT4_FREE_BLOCKS_FORGET;
	else if (ext4_should_journal_data(inode))
		flags |= EXT4_FREE_BLOCKS_FORGET;

	/*
	 * For bigalloc file systems, we never free a partial cluster
	 * at the beginning of the extent.  Instead, we make a note
	 * that we tried freeing the cluster, and check to see if we
	 * need to free it on a subsequent call to ext4_remove_blocks,
	 * or at the end of the ext4_truncate() operation.
	 */
	flags |= EXT4_FREE_BLOCKS_NOFREE_FIRST_CLUSTER;

	trace_ext4_remove_blocks(inode, ex, from, to, *partial_cluster);
	/*
	 * If we have a partial cluster, and it's different from the
	 * cluster of the last block, we need to explicitly free the
	 * partial cluster here.
	 */
	pblk = ext4_ext_pblock(ex) + ee_len - 1;
	if (*partial_cluster && (EXT4_B2C(sbi, pblk) != *partial_cluster)) {
		ext4_free_blocks(handle, inode, NULL,
				 EXT4_C2B(sbi, *partial_cluster),
				 sbi->s_cluster_ratio, flags);
		*partial_cluster = 0;
	}

#ifdef EXTENTS_STATS
	{
		struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
		spin_lock(&sbi->s_ext_stats_lock);
		sbi->s_ext_blocks += ee_len;
		sbi->s_ext_extents++;
		if (ee_len < sbi->s_ext_min)
			sbi->s_ext_min = ee_len;
		if (ee_len > sbi->s_ext_max)
			sbi->s_ext_max = ee_len;
		if (ext_depth(inode) > sbi->s_depth_max)
			sbi->s_depth_max = ext_depth(inode);
		spin_unlock(&sbi->s_ext_stats_lock);
	}
#endif
	if (from >= le32_to_cpu(ex->ee_block)
	    && to == le32_to_cpu(ex->ee_block) + ee_len - 1) {
		/* tail removal */
		ext4_lblk_t num;

		num = le32_to_cpu(ex->ee_block) + ee_len - from;
		pblk = ext4_ext_pblock(ex) + ee_len - num;
		ext_debug("free last %u blocks starting %llu\n", num, pblk);
		ext4_free_blocks(handle, inode, NULL, pblk, num, flags);
		/*
		 * If the block range to be freed didn't start at the
		 * beginning of a cluster, and we removed the entire
		 * extent, save the partial cluster here, since we
		 * might need to delete if we determine that the
		 * truncate operation has removed all of the blocks in
		 * the cluster.
		 */
		if (EXT4_PBLK_COFF(sbi, pblk) &&
		    (ee_len == num))
			*partial_cluster = EXT4_B2C(sbi, pblk);
		else
			*partial_cluster = 0;
	} else if (from == le32_to_cpu(ex->ee_block)
		   && to <= le32_to_cpu(ex->ee_block) + ee_len - 1) {
		/* head removal */
		ext4_lblk_t num;
		ext4_fsblk_t start;

		num = to - from;
		start = ext4_ext_pblock(ex);

		ext_debug("free first %u blocks starting %llu\n", num, start);
		ext4_free_blocks(handle, inode, NULL, start, num, flags);

	} else {
		printk(KERN_INFO "strange request: removal(2) "
				"%u-%u from %u:%u\n",
				from, to, le32_to_cpu(ex->ee_block), ee_len);
	}
	return 0;
}


/*
 * ext4_ext_rm_leaf() Removes the extents associated with the
 * blocks appearing between "start" and "end", and splits the extents
 * if "start" and "end" appear in the same extent
 *
 * @handle: The journal handle
 * @inode:  The files inode
 * @path:   The path to the leaf
 * @start:  The first block to remove
 * @end:   The last block to remove
 */
static int
ext4_ext_rm_leaf(handle_t *handle, struct inode *inode,
		 struct ext4_ext_path *path, ext4_fsblk_t *partial_cluster,
		 ext4_lblk_t start, ext4_lblk_t end)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	int err = 0, correct_index = 0;
	int depth = ext_depth(inode), credits;
	struct ext4_extent_header *eh;
	ext4_lblk_t a, b;
	unsigned num;
	ext4_lblk_t ex_ee_block;
	unsigned short ex_ee_len;
	unsigned uninitialized = 0;
	struct ext4_extent *ex;

	/* the header must be checked already in ext4_ext_remove_space() */
	ext_debug("truncate since %u in leaf to %u\n", start, end);
	if (!path[depth].p_hdr)
		path[depth].p_hdr = ext_block_hdr(path[depth].p_bh);
	eh = path[depth].p_hdr;
	if (unlikely(path[depth].p_hdr == NULL)) {
		EXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
		return -EIO;
	}
	/* find where to start removing */
	ex = EXT_LAST_EXTENT(eh);

	ex_ee_block = le32_to_cpu(ex->ee_block);
	ex_ee_len = ext4_ext_get_actual_len(ex);

	/*
	 * If we're starting with an extent other than the last one in the
	 * node, we need to see if it shares a cluster with the extent to
	 * the right (towards the end of the file). If its leftmost cluster
	 * is this extent's rightmost cluster and it is not cluster aligned,
	 * we'll mark it as a partial that is not to be deallocated.
	 */

	if (ex != EXT_LAST_EXTENT(eh)) {
		ext4_fsblk_t current_pblk, right_pblk;
		long long current_cluster, right_cluster;

		current_pblk = ext4_ext_pblock(ex) + ex_ee_len - 1;
		current_cluster = (long long)EXT4_B2C(sbi, current_pblk);
		right_pblk = ext4_ext_pblock(ex + 1);
		right_cluster = (long long)EXT4_B2C(sbi, right_pblk);
		if (current_cluster == right_cluster &&
			EXT4_PBLK_COFF(sbi, right_pblk))
			*partial_cluster = -right_cluster;
	}

	trace_ext4_ext_rm_leaf(inode, start, ex, *partial_cluster);

	while (ex >= EXT_FIRST_EXTENT(eh) &&
			ex_ee_block + ex_ee_len > start) {

		if (ext4_ext_is_uninitialized(ex))
			uninitialized = 1;
		else
			uninitialized = 0;

		ext_debug("remove ext %u:[%d]%d\n", ex_ee_block,
			 uninitialized, ex_ee_len);
		path[depth].p_ext = ex;

		a = ex_ee_block > start ? ex_ee_block : start;
		b = ex_ee_block+ex_ee_len - 1 < end ?
			ex_ee_block+ex_ee_len - 1 : end;

		ext_debug("  border %u:%u\n", a, b);

		/* If this extent is beyond the end of the hole, skip it */
		if (end < ex_ee_block) {
			ex--;
			ex_ee_block = le32_to_cpu(ex->ee_block);
			ex_ee_len = ext4_ext_get_actual_len(ex);
			continue;
		} else if (b != ex_ee_block + ex_ee_len - 1) {
			EXT4_ERROR_INODE(inode,
					 "can not handle truncate %u:%u "
					 "on extent %u:%u",
					 start, end, ex_ee_block,
					 ex_ee_block + ex_ee_len - 1);
			err = -EIO;
			goto out;
		} else if (a != ex_ee_block) {
			/* remove tail of the extent */
			num = a - ex_ee_block;
		} else {
			/* remove whole extent: excellent! */
			num = 0;
		}
		/*
		 * 3 for leaf, sb, and inode plus 2 (bmap and group
		 * descriptor) for each block group; assume two block
		 * groups plus ex_ee_len/blocks_per_block_group for
		 * the worst case
		 */
		credits = 7 + 2*(ex_ee_len/EXT4_BLOCKS_PER_GROUP(inode->i_sb));
		if (ex == EXT_FIRST_EXTENT(eh)) {
			correct_index = 1;
			credits += (ext_depth(inode)) + 1;
		}
		credits += EXT4_MAXQUOTAS_TRANS_BLOCKS(inode->i_sb);

		err = ext4_ext_truncate_extend_restart(handle, inode, credits);
		if (err)
			goto out;

		err = ext4_ext_get_access(handle, inode, path + depth);
		if (err)
			goto out;

		err = ext4_remove_blocks(handle, inode, ex, partial_cluster,
					 a, b);
		if (err)
			goto out;

		if (num == 0)
			/* this extent is removed; mark slot entirely unused */
			ext4_ext_store_pblock(ex, 0);

		ex->ee_len = cpu_to_le16(num);
		/*
		 * Do not mark uninitialized if all the blocks in the
		 * extent have been removed.
		 */
		if (uninitialized && num)
			ext4_ext_mark_uninitialized(ex);
		/*
		 * If the extent was completely released,
		 * we need to remove it from the leaf
		 */
		if (num == 0) {
			if (end != EXT_MAX_BLOCKS - 1) {
				/*
				 * For hole punching, we need to scoot all the
				 * extents up when an extent is removed so that
				 * we dont have blank extents in the middle
				 */
				memmove(ex, ex+1, (EXT_LAST_EXTENT(eh) - ex) *
					sizeof(struct ext4_extent));

				/* Now get rid of the one at the end */
				memset(EXT_LAST_EXTENT(eh), 0,
					sizeof(struct ext4_extent));
			}
			le16_add_cpu(&eh->eh_entries, -1);
		} else
			*partial_cluster = 0;

		err = ext4_ext_dirty(handle, inode, path + depth);
		if (err)
			goto out;

		ext_debug("new extent: %u:%u:%llu\n", ex_ee_block, num,
				ext4_ext_pblock(ex));
		ex--;
		ex_ee_block = le32_to_cpu(ex->ee_block);
		ex_ee_len = ext4_ext_get_actual_len(ex);
	}

	if (correct_index && eh->eh_entries)
		err = ext4_ext_correct_indexes(handle, inode, path);

	/*
	 * If there is still a entry in the leaf node, check to see if
	 * it references the partial cluster.  This is the only place
	 * where it could; if it doesn't, we can free the cluster.
	 */
	if (*partial_cluster && ex >= EXT_FIRST_EXTENT(eh) &&
	    (EXT4_B2C(sbi, ext4_ext_pblock(ex) + ex_ee_len - 1) !=
	     *partial_cluster)) {
		int flags = EXT4_FREE_BLOCKS_FORGET;

		if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode))
			flags |= EXT4_FREE_BLOCKS_METADATA;

		ext4_free_blocks(handle, inode, NULL,
				 EXT4_C2B(sbi, *partial_cluster),
				 sbi->s_cluster_ratio, flags);
		*partial_cluster = 0;
	}

	/* if this leaf is free, then we should
	 * remove it from index block above */
	if (err == 0 && eh->eh_entries == 0 && path[depth].p_bh != NULL)
		err = ext4_ext_rm_idx(handle, inode, path, depth);

out:
	return err;
}

/*
 * ext4_ext_more_to_rm:
 * returns 1 if current index has to be freed (even partial)
 */
static int
ext4_ext_more_to_rm(struct ext4_ext_path *path)
{
	BUG_ON(path->p_idx == NULL);

	if (path->p_idx < EXT_FIRST_INDEX(path->p_hdr))
		return 0;

	/*
	 * if truncate on deeper level happened, it wasn't partial,
	 * so we have to consider current index for truncation
	 */
	if (le16_to_cpu(path->p_hdr->eh_entries) == path->p_block)
		return 0;
	return 1;
}

int ext4_ext_remove_space(struct inode *inode, ext4_lblk_t start,
			  ext4_lblk_t end)
{
	struct super_block *sb = inode->i_sb;
	int depth = ext_depth(inode);
	struct ext4_ext_path *path = NULL;
	ext4_fsblk_t partial_cluster = 0;
	handle_t *handle;
	int i = 0, err = 0;

	ext_debug("truncate since %u to %u\n", start, end);

	/* probably first extent we're gonna free will be last in block */
	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, depth + 1);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

again:
	trace_ext4_ext_remove_space(inode, start, depth);

	/*
	 * Check if we are removing extents inside the extent tree. If that
	 * is the case, we are going to punch a hole inside the extent tree
	 * so we have to check whether we need to split the extent covering
	 * the last block to remove so we can easily remove the part of it
	 * in ext4_ext_rm_leaf().
	 */
	if (end < EXT_MAX_BLOCKS - 1) {
		struct ext4_extent *ex;
		ext4_lblk_t ee_block;

		/* find extent for this block */
		path = ext4_ext_find_extent(inode, end, NULL);
		if (IS_ERR(path)) {
			ext4_journal_stop(handle);
			return PTR_ERR(path);
		}
		depth = ext_depth(inode);
		/* Leaf not may not exist only if inode has no blocks at all */
		ex = path[depth].p_ext;
		if (!ex) {
			if (depth) {
				EXT4_ERROR_INODE(inode,
						 "path[%d].p_hdr == NULL",
						 depth);
				err = -EIO;
			}
			goto out;
		}

		ee_block = le32_to_cpu(ex->ee_block);

		/*
		 * See if the last block is inside the extent, if so split
		 * the extent at 'end' block so we can easily remove the
		 * tail of the first part of the split extent in
		 * ext4_ext_rm_leaf().
		 */
		if (end >= ee_block &&
		    end < ee_block + ext4_ext_get_actual_len(ex) - 1) {
			int split_flag = 0;

			if (ext4_ext_is_uninitialized(ex))
				split_flag = EXT4_EXT_MARK_UNINIT1 |
					     EXT4_EXT_MARK_UNINIT2;

			/*
			 * Split the extent in two so that 'end' is the last
			 * block in the first new extent. Also we should not
			 * fail removing space due to ENOSPC so try to use
			 * reserved block if that happens.
			 */
			err = ext4_split_extent_at(handle, inode, path,
					end + 1, split_flag,
					EXT4_GET_BLOCKS_PRE_IO |
					EXT4_GET_BLOCKS_METADATA_NOFAIL);

			if (err < 0)
				goto out;
		}
	}
	/*
	 * We start scanning from right side, freeing all the blocks
	 * after i_size and walking into the tree depth-wise.
	 */
	depth = ext_depth(inode);
	if (path) {
		int k = i = depth;
		while (--k > 0)
			path[k].p_block =
				le16_to_cpu(path[k].p_hdr->eh_entries)+1;
	} else {
		path = kzalloc(sizeof(struct ext4_ext_path) * (depth + 1),
			       GFP_NOFS);
		if (path == NULL) {
			ext4_journal_stop(handle);
			return -ENOMEM;
		}
		path[0].p_depth = depth;
		path[0].p_hdr = ext_inode_hdr(inode);
		i = 0;

		if (ext4_ext_check(inode, path[0].p_hdr, depth)) {
			err = -EIO;
			goto out;
		}
	}
	err = 0;

	while (i >= 0 && err == 0) {
		if (i == depth) {
			/* this is leaf block */
			err = ext4_ext_rm_leaf(handle, inode, path,
					       &partial_cluster, start,
					       end);
			/* root level has p_bh == NULL, brelse() eats this */
			brelse(path[i].p_bh);
			path[i].p_bh = NULL;
			i--;
			continue;
		}

		/* this is index block */
		if (!path[i].p_hdr) {
			ext_debug("initialize header\n");
			path[i].p_hdr = ext_block_hdr(path[i].p_bh);
		}

		if (!path[i].p_idx) {
			/* this level hasn't been touched yet */
			path[i].p_idx = EXT_LAST_INDEX(path[i].p_hdr);
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries)+1;
			ext_debug("init index ptr: hdr 0x%p, num %d\n",
				  path[i].p_hdr,
				  le16_to_cpu(path[i].p_hdr->eh_entries));
		} else {
			/* we were already here, see at next index */
			path[i].p_idx--;
		}

		ext_debug("level %d - index, first 0x%p, cur 0x%p\n",
				i, EXT_FIRST_INDEX(path[i].p_hdr),
				path[i].p_idx);
		if (ext4_ext_more_to_rm(path + i)) {
			struct buffer_head *bh;
			/* go to the next level */
			ext_debug("move to level %d (block %llu)\n",
				  i + 1, ext4_idx_pblock(path[i].p_idx));
			memset(path + i + 1, 0, sizeof(*path));
			bh = sb_bread(sb, ext4_idx_pblock(path[i].p_idx));
			if (!bh) {
				/* should we reset i_size? */
				err = -EIO;
				break;
			}
			if (WARN_ON(i + 1 > depth)) {
				err = -EIO;
				break;
			}
			if (ext4_ext_check_block(inode, ext_block_hdr(bh),
							depth - i - 1, bh)) {
				err = -EIO;
				break;
			}
			path[i + 1].p_bh = bh;

			/* save actual number of indexes since this
			 * number is changed at the next iteration */
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries);
			i++;
		} else {
			/* we finished processing this index, go up */
			if (path[i].p_hdr->eh_entries == 0 && i > 0) {
				/* index is empty, remove it;
				 * handle must be already prepared by the
				 * truncatei_leaf() */
				err = ext4_ext_rm_idx(handle, inode, path, i);
			}
			/* root level has p_bh == NULL, brelse() eats this */
			brelse(path[i].p_bh);
			path[i].p_bh = NULL;
			i--;
			ext_debug("return to level %d\n", i);
		}
	}

	trace_ext4_ext_remove_space_done(inode, start, depth, partial_cluster,
			path->p_hdr->eh_entries);

	/* If we still have something in the partial cluster and we have removed
	 * even the first extent, then we should free the blocks in the partial
	 * cluster as well. */
	if (partial_cluster && path->p_hdr->eh_entries == 0) {
		int flags = EXT4_FREE_BLOCKS_FORGET;

		if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode))
			flags |= EXT4_FREE_BLOCKS_METADATA;

		ext4_free_blocks(handle, inode, NULL,
				 EXT4_C2B(EXT4_SB(sb), partial_cluster),
				 EXT4_SB(sb)->s_cluster_ratio, flags);
		partial_cluster = 0;
	}

	/* TODO: flexible tree reduction should be here */
	if (path->p_hdr->eh_entries == 0) {
		/*
		 * truncate to zero freed all the tree,
		 * so we need to correct eh_depth
		 */
		err = ext4_ext_get_access(handle, inode, path);
		if (err == 0) {
			ext_inode_hdr(inode)->eh_depth = 0;
			ext_inode_hdr(inode)->eh_max =
				cpu_to_le16(ext4_ext_space_root(inode, 0));
			err = ext4_ext_dirty(handle, inode, path);
		}
	}
out:
	ext4_ext_drop_refs(path);
	kfree(path);
	if (err == -EAGAIN) {
		path = NULL;
		goto again;
	}
	ext4_journal_stop(handle);

	return err;
}

/*
 * called at mount time
 */
void ext4_ext_init(struct super_block *sb)
{
	/*
	 * possible initialization would be here
	 */

	if (EXT4_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_EXTENTS)) {
#if defined(AGGRESSIVE_TEST) || defined(CHECK_BINSEARCH) || defined(EXTENTS_STATS)
		printk(KERN_INFO "EXT4-fs: file extents enabled"
#ifdef AGGRESSIVE_TEST
		       ", aggressive tests"
#endif
#ifdef CHECK_BINSEARCH
		       ", check binsearch"
#endif
#ifdef EXTENTS_STATS
		       ", stats"
#endif
		       "\n");
#endif
#ifdef EXTENTS_STATS
		spin_lock_init(&EXT4_SB(sb)->s_ext_stats_lock);
		EXT4_SB(sb)->s_ext_min = 1 << 30;
		EXT4_SB(sb)->s_ext_max = 0;
#endif
	}
}

/*
 * called at umount time
 */
void ext4_ext_release(struct super_block *sb)
{
	if (!EXT4_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_EXTENTS))
		return;

#ifdef EXTENTS_STATS
	if (EXT4_SB(sb)->s_ext_blocks && EXT4_SB(sb)->s_ext_extents) {
		struct ext4_sb_info *sbi = EXT4_SB(sb);
		printk(KERN_ERR "EXT4-fs: %lu blocks in %lu extents (%lu ave)\n",
			sbi->s_ext_blocks, sbi->s_ext_extents,
			sbi->s_ext_blocks / sbi->s_ext_extents);
		printk(KERN_ERR "EXT4-fs: extents: %lu min, %lu max, max depth %lu\n",
			sbi->s_ext_min, sbi->s_ext_max, sbi->s_depth_max);
	}
#endif
}

/* FIXME!! we need to try to merge to left or right after zero-out  */
static int ext4_ext_zeroout(struct inode *inode, struct ext4_extent *ex)
{
	ext4_fsblk_t ee_pblock;
	unsigned int ee_len;
	int ret;

	ee_len    = ext4_ext_get_actual_len(ex);
	ee_pblock = ext4_ext_pblock(ex);

	ret = sb_issue_zeroout(inode->i_sb, ee_pblock, ee_len, GFP_NOFS);
	if (ret > 0)
		ret = 0;

	return ret;
}

/*
 * ext4_split_extent_at() splits an extent at given block.
 *
 * @handle: the journal handle
 * @inode: the file inode
 * @path: the path to the extent
 * @split: the logical block where the extent is splitted.
 * @split_flags: indicates if the extent could be zeroout if split fails, and
 *		 the states(init or uninit) of new extents.
 * @flags: flags used to insert new extent to extent tree.
 *
 *
 * Splits extent [a, b] into two extents [a, @split) and [@split, b], states
 * of which are deterimined by split_flag.
 *
 * There are two cases:
 *  a> the extent are splitted into two extent.
 *  b> split is not needed, and just mark the extent.
 *
 * return 0 on success.
 */
//ext4_ext_map_blocks()->ext4_ext_handle_uninitialized_extents()/ext4_ext_handle_unwritten_extents()->
//ext4_ext_convert_to_initialized()->ext4_split_extent()->ext4_split_extent_at()

/*以split这个逻辑块地址为分割点，把path[depth].p_ext指向的ext4_extent结构(即ex)的逻辑块范围ee_block~(ee_block+ee_len)分割成
ee_block~split和split~(ee_block+ee_len)，然后把后半段split~(ee_block+ee_len)对应的ext4_extent结构添加到ext4 extent B+树*/
static int ext4_split_extent_at(handle_t *handle,
			     struct inode *inode,
			     struct ext4_ext_path *path,
			     ext4_lblk_t split,//map->m_lblk + map->m_len
			     int split_flag,
			     int flags)
{
	ext4_fsblk_t newblock;
	ext4_lblk_t ee_block;
	struct ext4_extent *ex, newex, orig_ex, zero_ex;
	struct ext4_extent *ex2 = NULL;
	unsigned int ee_len, depth;
	int err = 0;

	BUG_ON((split_flag & (EXT4_EXT_DATA_VALID1 | EXT4_EXT_DATA_VALID2)) ==
	       (EXT4_EXT_DATA_VALID1 | EXT4_EXT_DATA_VALID2));

	ext_debug("ext4_split_extents_at: inode %lu, logical"
		"block %llu\n", inode->i_ino, (unsigned long long)split);

	ext4_ext_show_leaf(inode, path);

	depth = ext_depth(inode);
    //ext4 extent B+树叶子节点，指向起始逻辑块地址最接近map->m_lblk这个起始逻辑块地址的ext4_extent
	ex = path[depth].p_ext;
    //ext4 extent B+树叶子节点，ext4_extent结构代表的起始逻辑块地址
	ee_block = le32_to_cpu(ex->ee_block);
    //ext4 extent B+树叶子节点，ext4_extent结构代表的映射的物理块个数
	ee_len = ext4_ext_get_actual_len(ex);
    //ee_block是ex起始逻辑块地址，split是分割点的逻辑块地址，split>ee_block，二者都在ex这个
    //ext4_extent的逻辑块范围内。newblock是分割点的逻辑块地址对应的物理块地址
	newblock = split - ee_block + ext4_ext_pblock(ex);

	BUG_ON(split < ee_block || split >= (ee_block + ee_len));
	BUG_ON(!ext4_ext_is_uninitialized(ex) &&
	       split_flag & (EXT4_EXT_MAY_ZEROOUT |
			     EXT4_EXT_MARK_UNINIT1 |
			     EXT4_EXT_MARK_UNINIT2));

	err = ext4_ext_get_access(handle, inode, path + depth);
	if (err)
		goto out;

    //分割点的逻辑块地址等于ex起始逻辑块地址，不用分割
	if (split == ee_block) {
		/*
		 * case b: block @split is the block that the extent begins with
		 * then we just change the state of the extent, and splitting
		 * is not needed.
		 */
		if (split_flag & EXT4_EXT_MARK_UNINIT2)
			ext4_ext_mark_uninitialized(ex);//有"UNINIT2"标记就要标记ex "uninitialized"
		else
			ext4_ext_mark_initialized(ex);//标记ex初始化

		if (!(flags & EXT4_GET_BLOCKS_PRE_IO))
            //尝试把ex前后的ext4_extent结构的逻辑块和物理块地址合并到ex
			ext4_ext_try_to_merge(handle, inode, path, ex);

        //ext4_extent映射的逻辑块范围可能发生变化了，标记对应的物理块映射的bh或者文件inode脏.
		err = ext4_ext_dirty(handle, inode, path + path->p_depth);
		goto out;
	}

    /*下边这是把ex的逻辑块分割成两部分(ee_block~split)和(split~ee_block+ee_len)。分割后，ex新的
    逻辑块范围是(ee_block~split)，ex2的逻辑块范围是(split~ee_block+ee_len)
    */
	/* case a */
    //orig_ex先保存ex原有数据
	memcpy(&orig_ex, ex, sizeof(orig_ex));
    /*重点，标记ex->ee_len为映射的block数，这样ex就是被标记初始化状态了，因为ex->ee_len只要不是没被标记EXT_INIT_MAX_LEN，就是初始化状态*/
	ex->ee_len = cpu_to_le16(split - ee_block);
	if (split_flag & EXT4_EXT_MARK_UNINIT1)
		ext4_ext_mark_uninitialized(ex);//有EXT4_EXT_MARK_UNINIT1标记再把ex标记未初始化

	/*
	 * path may lead to new leaf, not to original leaf any more
	 * after ext4_ext_insert_extent() returns,
	 */
	err = ext4_ext_dirty(handle, inode, path + depth);
	if (err)
		goto fix_extent_len;

	ex2 = &newex;//ex2获得ex分割后的后半段的逻辑块范围
	ex2->ee_block = cpu_to_le32(split);//ex2的逻辑块起始地址
	ex2->ee_len   = cpu_to_le16(ee_len - (split - ee_block));//ex2逻辑块个数
	ext4_ext_store_pblock(ex2, newblock);//ex2的起始物理块地址
	if (split_flag & EXT4_EXT_MARK_UNINIT2)
		ext4_ext_mark_uninitialized(ex2);

    //把分割的后半段ex2添加到ext4 extent B+树
	err = ext4_ext_insert_extent(handle, inode, path, &newex, flags);

    //err是ENOSPC一般不会成立吧
	if (err == -ENOSPC && (EXT4_EXT_MAY_ZEROOUT & split_flag)) {
		if (split_flag & (EXT4_EXT_DATA_VALID1|EXT4_EXT_DATA_VALID2)) {
			if (split_flag & EXT4_EXT_DATA_VALID1) {
				err = ext4_ext_zeroout(inode, ex2);
				zero_ex.ee_block = ex2->ee_block;
				zero_ex.ee_len = cpu_to_le16(
						ext4_ext_get_actual_len(ex2));
				ext4_ext_store_pblock(&zero_ex,
						      ext4_ext_pblock(ex2));
			} else {
				err = ext4_ext_zeroout(inode, ex);
				zero_ex.ee_block = ex->ee_block;
				zero_ex.ee_len = cpu_to_le16(
						ext4_ext_get_actual_len(ex));
				ext4_ext_store_pblock(&zero_ex,
						      ext4_ext_pblock(ex));
			}
		} else {
			err = ext4_ext_zeroout(inode, &orig_ex);
			zero_ex.ee_block = orig_ex.ee_block;
			zero_ex.ee_len = cpu_to_le16(
						ext4_ext_get_actual_len(&orig_ex));
			ext4_ext_store_pblock(&zero_ex,
					      ext4_ext_pblock(&orig_ex));
		}

		if (err)
			goto fix_extent_len;
		/* update the extent length and mark as initialized */
		ex->ee_len = cpu_to_le16(ee_len);
		ext4_ext_try_to_merge(handle, inode, path, ex);
		err = ext4_ext_dirty(handle, inode, path + path->p_depth);
		if (err)
			goto fix_extent_len;

		/* update extent status tree */
		err = ext4_es_zeroout(inode, &zero_ex);

		goto out;
	}
    else if (err)//这里一般也不成立
		goto fix_extent_len;

out:
	ext4_ext_show_leaf(inode, path);
	return err;//一般这里返回0

fix_extent_len:
    //显然这是ex split失败，进而恢复ex原有的数据
	ex->ee_len = orig_ex.ee_len;
	ext4_ext_dirty(handle, inode, path + depth);
	return err;
}

/*
 * ext4_split_extents() splits an extent and mark extent which is covered
 * by @map as split_flags indicates
 *
 * It may result in splitting the extent into multiple extents (upto three)
 * There are three possibilities:
 *   a> There is no split required
 *   b> Splits in two extents: Split is happening at either end of the extent
 *   c> Splits in three extents: Somone is splitting in middle of the extent
 *
 */
//ext4_ext_map_blocks()->ext4_ext_handle_uninitialized_extents()/ext4_ext_handle_unwritten_extents()->ext4_ext_convert_to_initialized()
//->ext4_split_extent()

/*ex = path[depth].p_ext
  在这里，map->m_lblk大于ex的起始逻辑块地址ee_block是可以保证的。即map的起始逻辑块地址map->m_lblk肯定在ex的逻辑块范围内。
  现在执行ext4_split_extent()把ex的逻辑块范围ee_block~(ee_block + ee_len)进行分割，分割情况有几种
1:如果 map->m_lblk +map->m_len 小于ee_block + ee_len，即map的结束逻辑块地址小于ex的结束逻辑块地址。则把ex的逻辑块范围分割成3段
 ee_block~map->m_lblk 和 map->m_lblk~(map->m_lblk +map->m_len) 和 (map->m_lblk +map->m_len)~(ee_block + ee_len)。这种情况，就能
 保证本次要求映射的map->m_len个逻辑块都能完成映射，即allocated =map->m_len。

 具体细节是:
 1.1:if (map->m_lblk + map->m_len < ee_block + ee_len)成立，split_flag1 |= EXT4_EXT_MARK_UNINIT1|EXT4_EXT_MARK_UNINIT2,然后
 执行ext4_split_extent_at()以map->m_lblk + map->m_len这个逻辑块地址为分割点，把path[depth].p_ext指向的ext4_extent结构(即ex)的逻辑块范围
 ee_block~(ee_block+ee_len)分割成ee_block~(map->m_lblk + map->m_len)和(map->m_lblk + map->m_len)~(ee_block+ee_len)这两个ext4_extent，
 前半段的ext4_extent还是ex，只是映射的逻辑块个数减少了(ee_block+ee_len)-(map->m_lblk + map->m_len)，后半段的是个新的ext4_extent。
 因为split_flag1 |= EXT4_EXT_MARK_UNINIT1|EXT4_EXT_MARK_UNINIT2，则还要标记这两个ext4_extent结构"未初始化状态"。然后把后半段
 map->m_lblk + map->m_len)~(ee_block+ee_len)对应的ext4_extent结构添加到ext4 extent B+树。

 回到ext4_split_extent()函数，ext4_ext_find_extent(inode, map->m_lblk, path)后path[depth].p_ext大概率还是老的ex。
 1.2 if (map->m_lblk >= ee_block)肯定成立，
 里边的if (uninitialized)成立，if (uninitialized)里边的split_flag1 |= EXT4_EXT_MARK_UNINIT1，可能会去掉EXT4_EXT_MARK_UNINIT2标记。
 接着，再次执行ext4_split_extent_at(),以map->m_lblk这个逻辑块地址为分割点，把path[depth].p_ext指向的ext4_extent结构(即ex)的逻辑块范围
 ee_block~(ee_block+ee_len)分割成ee_block~map->m_lblk和map->m_lblk~(ee_block+ee_len)两个ext4_extent结构。前半段的ext4_extent结构还是
 ex，但是逻辑块数减少了(ee_block+ee_len)-map->m_lblk个。因为此时split_flag1只有EXT4_EXT_MARK_UNINIT1标记，可能会去掉
 EXT4_EXT_MARK_UNINIT2标记，则再对ex加上"未初始化状态"，后半段的ext4_extent可能会被去掉"未初始化状态"。接着，把后半段的ext4_extent
 结构添加到ext4 extent B+树。

 这里有个特例，就是 if (map->m_lblk >= ee_block)里的map->m_lblk == ee_block，则执行ext4_split_extent_at()函数时，不会再分割ex，
 里边if (split == ee_block)成立，可能会执行ext4_ext_mark_initialized(ex)标记ex是"初始化状态"，终于转正了。
 
2:如果 map->m_lblk +map->m_len 大于等于ee_block + ee_len，即map的结束逻辑块地址大于ex的结束逻辑块地址。则把ex的逻辑块范围分割成2段
 ee_block~map->m_lblk 和 map->m_lblk~(ee_block + ee_len)，这种情况，不能保证本次要求映射的map->m_len个逻辑块都完成映射。只能映射
 (ee_block + ee_len) - map->m_lblk个逻辑块，即allocated =(ee_block + ee_len) - map->m_lblk。

 具体细节参见1.2
*/
static int ext4_split_extent(handle_t *handle,
			      struct inode *inode,
			      struct ext4_ext_path *path,
			      struct ext4_map_blocks *map,
			      int split_flag,
			      int flags)
{
	ext4_lblk_t ee_block;
	struct ext4_extent *ex;
	unsigned int ee_len, depth;
	int err = 0;
	int uninitialized;
	int split_flag1, flags1;
	int allocated = map->m_len;

	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);
    //ex是否是未初始化状态
	uninitialized = ext4_ext_is_uninitialized(ex);

    //如果map的结束逻辑块地址小于ex的结束逻辑块地址，则执行ext4_split_extent_at()把ex的逻辑块地址分割为
    //ee_block~(map->m_lblk+map->m_len)和(map->m_lblk+map->m_len)~(ee_block + ee_len)。下边的if (map->m_lblk >= ee_block)
    //也成立，再次执行ext4_split_extent_at()把ex的逻辑块范围ee_block~(map->m_lblk+map->m_len)分割成ee_block~map->m_lblk
    //和m_lblk~(map->m_lblk+map->m_len)两段，后边的m_lblk~(map->m_lblk+map->m_len)这map->m_len个逻辑块
    //最终完成了map的逻辑块与物理块的映射。
	if (map->m_lblk + map->m_len < ee_block + ee_len) {
		split_flag1 = split_flag & EXT4_EXT_MAY_ZEROOUT;
        
		flags1 = flags | EXT4_GET_BLOCKS_PRE_IO;//flag加上EXT4_GET_BLOCKS_PRE_IO标记
		//如果ex有未初始化标记，则split_flag1被加上EXT4_EXT_MARK_UNINIT1和EXT4_EXT_MARK_UNINIT2标记。EXT4_EXT_MARK_UNINIT1是标记
		//分割的前半段ext4_extent未初始化状态,EXT4_EXT_MARK_UNINIT2是标记分割的后半段ext4_extent未初始化状态
		if (uninitialized)
			split_flag1 |= EXT4_EXT_MARK_UNINIT1 |
				       EXT4_EXT_MARK_UNINIT2;
        
		if (split_flag & EXT4_EXT_DATA_VALID2)
			split_flag1 |= EXT4_EXT_DATA_VALID1;
        /*以map->m_lblk + map->m_len这个逻辑块地址为分割点，把path[depth].p_ext指向的ext4_extent结构(即ex)的逻辑块范围
        ee_block~(ee_block+ee_len)分割成ee_block~(map->m_lblk + map->m_len)和(map->m_lblk + map->m_len)~(ee_block+ee_len)，
        然后把后半段map->m_lblk + map->m_len)~(ee_block+ee_len)对应的ext4_extent结构添加到ext4 extent B+树*/
		err = ext4_split_extent_at(handle, inode, path,
				map->m_lblk + map->m_len, split_flag1, flags1);
		if (err)
			goto out;
	} else {
	    //到这里，说明map的结束逻辑块地址大于ex的结束逻辑块地址，则allocated=(ee_len+ee_block)-map->m_lblk，即map只能用到ex逻辑块范围
	    //里的allocated个逻辑块，下边if (map->m_lblk >= ee_block)肯定成立，执行ext4_split_extent_at()把ex的逻辑块范围分割成
	    //ee_block~map->m_lblk 和 map->m_lblk~(ee_block + ee_len)。map->m_lblk~(ee_block + ee_len)是map本身映射的逻辑块，没有达到map->len个
		allocated = ee_len - (map->m_lblk - ee_block);
	}
	/*
	 * Update path is required because previous ext4_split_extent_at() may
	 * result in split of original leaf or extent zeroout.
	 */
	ext4_ext_drop_refs(path);
    //上边可能把ex的逻辑块范围分割了，这里重新再ext4 extent B+树查找逻辑块地址范围接近map->m_lblk的索引节点和叶子结点
	path = ext4_ext_find_extent(inode, map->m_lblk, path);
	if (IS_ERR(path))
		return PTR_ERR(path);
	depth = ext_depth(inode);
	ex = path[depth].p_ext;
    //ex是否是未初始化状态
	uninitialized = ext4_ext_is_uninitialized(ex);
	split_flag1 = 0;
    
    //如果map的起始逻辑块地址大于ex的起始逻辑块地址，以map->m_lblk为分割点，再次分割新的ex逻辑块范围
	if (map->m_lblk >= ee_block) {
		split_flag1 = split_flag & EXT4_EXT_DATA_VALID2;

        //如果ex有未初始化标记，则split_flag1被加上EXT4_EXT_MARK_UNINIT1标记，EXT4_EXT_MARK_UNINIT1是标记分割的前半段ext4_extent未初始化状态
		if (uninitialized) {
			split_flag1 |= EXT4_EXT_MARK_UNINIT1;
			split_flag1 |= split_flag & (EXT4_EXT_MAY_ZEROOUT |
						     EXT4_EXT_MARK_UNINIT2);
		}
        /*以map->m_lblk这个逻辑块地址为分割点，把path[depth].p_ext指向的ext4_extent结构(即ex)的逻辑块范围ee_block~(ee_block+ee_len)分割
        成ee_block~map->m_lblk和map->m_lblk~(ee_block+ee_len)，然后把后半段map->m_lblk~(ee_block+ee_len)对应的ext4_extent
        结构添加到ext4 extent B+树。注意，上边的ext4_split_extent_at()对原始ex的进行了分割，然后ext4_ext_find_extent()
        重新再ext4 extent B+树查找逻辑块地址范围接近map->m_lblk的索引节点和叶子结点，到这里的ext4_split_extent_at()，path[depth].p_ext
        指向的ext4_extent结构逻辑块范围可能变了。*/
		err = ext4_split_extent_at(handle, inode, path,
				map->m_lblk, split_flag1, flags);
		if (err)
			goto out;
	}

	ext4_ext_show_leaf(inode, path);
out:
	return err ? err : allocated;
}

/*
 * This function is called by ext4_ext_map_blocks() if someone tries to write
 * to an uninitialized extent. It may result in splitting the uninitialized
 * extent into multiple extents (up to three - one initialized and two
 * uninitialized).
 * There are three possibilities:
 *   a> There is no split required: Entire extent should be initialized
 *   b> Splits in two extents: Write is happening at either end of the extent
 *   c> Splits in three extents: Somone is writing in middle of the extent
 *
 * Pre-conditions:
 *  - The extent pointed to by 'path' is uninitialized.
 *  - The extent pointed to by 'path' contains a superset
 *    of the logical span [map->m_lblk, map->m_lblk + map->m_len).
 *
 * Post-conditions on success:
 *  - the returned value is the number of blocks beyond map->l_lblk
 *    that are allocated and initialized.
 *    It is guaranteed to be >= map->m_len.
 */
//ext4_ext_map_blocks()->ext4_ext_handle_uninitialized_extents()/ext4_ext_handle_unwritten_extents()->ext4_ext_convert_to_initialized()
//执行到这里，path[depth].p_ext指向的ext4_extent是未初始化状态。注意，执行到这里，可以保证map->m_lblk在path[depth].p_ext即ex的逻辑块
//范围内的，即ee_block <= map->m_lblk <ee_len。
static int ext4_ext_convert_to_initialized(handle_t *handle,
					   struct inode *inode,
					   struct ext4_map_blocks *map,
					   struct ext4_ext_path *path,
					   int flags)
{
	struct ext4_sb_info *sbi;
	struct ext4_extent_header *eh;
	struct ext4_map_blocks split_map;
	struct ext4_extent zero_ex;
	struct ext4_extent *ex, *abut_ex;
	ext4_lblk_t ee_block, eof_block;
	unsigned int ee_len, depth, map_len = map->m_len;
	int allocated = 0, max_zeroout = 0;
	int err = 0;
	int split_flag = 0;

	ext_debug("ext4_ext_convert_to_initialized: inode %lu, logical"
		"block %llu, max_blocks %u\n", inode->i_ino,
		(unsigned long long)map->m_lblk, map_len);

	sbi = EXT4_SB(inode->i_sb);
	eof_block = (inode->i_size + inode->i_sb->s_blocksize - 1) >>
		inode->i_sb->s_blocksize_bits;
	if (eof_block < map->m_lblk + map_len)
		eof_block = map->m_lblk + map_len;

    //ext4 extent B+树深度
	depth = ext_depth(inode);
    //指向ext4 extent B+树叶子节点头部
	eh = path[depth].p_hdr;
    //ext4 extent B+树叶子节点，指向起始逻辑块地址最接近map->m_lblk这个起始逻辑块地址的ext4_extent
	ex = path[depth].p_ext;
    //叶子节点ext4_extent结构代表的起始逻辑块地址
	ee_block = le32_to_cpu(ex->ee_block);
    //ext4 extent B+树叶子节点，ext4_extent结构映射的物理块个数
	ee_len = ext4_ext_get_actual_len(ex);
	zero_ex.ee_len = 0;

	trace_ext4_ext_convert_to_initialized_enter(inode, map, ex);

	/* Pre-conditions */
	BUG_ON(!ext4_ext_is_uninitialized(ex));
	BUG_ON(!in_range(map->m_lblk, ee_block, ee_len));

	/*
	 * Attempt to transfer newly initialized blocks from the currently
	 * uninitialized extent to its neighbor. This is much cheaper
	 * than an insertion followed by a merge as those involve costly
	 * memmove() calls. Transferring to the left is the common case in
	 * steady state for workloads doing fallocate(FALLOC_FL_KEEP_SIZE)
	 * followed by append writes.
	 *
	 * Limitations of the current logic:
	 *  - L1: we do not deal with writes covering the whole extent.
	 *    This would require removing the extent if the transfer
	 *    is possible.
	 *  - L2: we only attempt to merge with an extent stored in the
	 *    same extent tree node.
	 */

    /*下边这两个大的if判断，在要求映射的物理块数map_len要小于ex已经映射的物理块数ee_len
    的情况下，如果ex前边或者后边的ext4_extent结构abut_ex，逻辑块地址紧挨着:1 ex的起始逻辑
    块地址是它前边的ext4_extent即abut_ex的结束逻辑块地址;2 ex的结束逻辑块地址是它后边的
    ext4_extent即abut_ex的起始逻辑块地址。这两种情况，都是把ex靠前或者靠后的map_len个逻辑块
    合并到abut_ex，ex的逻辑块个数只剩下ee_len-map_len。合并后，ex设置成未初始化状态
    ，abut_ex保持初始化状态。allocated是abut_ex增加的逻辑块个数map_len，如果没有发生合并
    则allocated保持0*/
    
	//要映射的起始逻辑块地址map->m_lblk等于ex的起始逻辑块地址
	if ((map->m_lblk == ee_block) &&
		/* See if we can merge left */
		(map_len < ee_len) &&		/*L1*///要求映射的物理块数map_len要小于ex已经映射的物理块数ee_len
		//ex是指向叶子节点ext4_extent_header后第2个及以后ext4_extent结构
		(ex > EXT_FIRST_EXTENT(eh))) {	/*L2*/
		ext4_lblk_t prev_lblk;
		ext4_fsblk_t prev_pblk, ee_pblk;
		unsigned int prev_len;

        //abut_ex指向ex上一个struct ext4_extent结构
		abut_ex = ex - 1;
		//上一个struct ext4_extent结构代表的起始逻辑块地址
		prev_lblk = le32_to_cpu(abut_ex->ee_block);
        //上一个struct ext4_extent结构映射的物理块个数
		prev_len = ext4_ext_get_actual_len(abut_ex);
        //上一个struct ext4_extent结构代表的起始物理块地址
		prev_pblk = ext4_ext_pblock(abut_ex);
        //ex这个struct ext4_extent结构代表的起始物理块地址
		ee_pblk = ext4_ext_pblock(ex);

		/*
		 * A transfer of blocks from 'ex' to 'abut_ex' is allowed
		 * upon those conditions:
		 * - C1: abut_ex is initialized,
		 * - C2: abut_ex is logically abutting ex,
		 * - C3: abut_ex is physically abutting ex,
		 * - C4: abut_ex can receive the additional blocks without
		 *   overflowing the (initialized) length limit.
		 */
		 
		/*ex前边的ext4_extent即abut_ex。abut_ex已经初始化过，并且abut_ex和ex紧挨着，并且
        要求映射的物理块数map_len要小于ex已经映射的物理块数ee_len。此时，abut_ex吞并了ex的
        逻辑块范围:把ex之前的逻辑块范围ee_block~ee_block+map_len划分给abut_ex这个
        ext4_extent，ex新的逻辑块地址范围是(ee_block + map_len)~(ee_block + ee_len)这一小片*/
		if ((!ext4_ext_is_uninitialized(abut_ex)) &&/*C1*///abut_ex必须是初始化状态
             //abut_ex的逻辑块地址和物理块地址与ex的紧挨着
            ((prev_lblk + prev_len) == ee_block) &&	/*C2*/
			((prev_pblk + prev_len) == ee_pblk) &&		/*C3*/
			//abut_ex和ex的映射的物理块个数总和小于0x8000，一个ext4_extent结构最大映射的
			//物理块个数不能超过0x8000，这是要把abut_ex和ex这两个ext4_extent合并???
			(prev_len < (EXT_INIT_MAX_LEN - map_len))) /*C4*/
		{
			err = ext4_ext_get_access(handle, inode, path + depth);
			if (err)
				goto out;

			trace_ext4_ext_convert_to_initialized_fastpath(inode,
				map, ex, abut_ex);

			/* Shift the start of ex by 'map_len' blocks */
            //下边是重新划分ex这个ext4_extent结构的势力范围，把之前ee_block~ee_block+map_len
            //划分给abut_ex这个ext4_extent，ex新的逻辑块地址范围是(ee_block + map_len)~
            //(ee_block + ee_len)
			ex->ee_block = cpu_to_le32(ee_block + map_len);//设置新的逻辑块首地址
			ext4_ext_store_pblock(ex, ee_pblk + map_len);//设置新的物理块首地址
			ex->ee_len = cpu_to_le16(ee_len - map_len);//设置新的映射的物理块个数
            /*把ex这个ext4_extent设置"uninitialized"标记，这是重点*/
			ext4_ext_mark_uninitialized(ex); /* Restore the flag */

			/* Extend abut_ex by 'map_len' blocks */
			abut_ex->ee_len = cpu_to_le16(prev_len + map_len);//ee_len映射的物理块个数增加map_len个

			/* Result: number of initialized blocks past m_lblk */
            //allocated是abut_ex增大的逻辑块个数
			allocated = map_len;
		}
	} 
    //要映射的结束逻辑块地址map->m_lblk+map_len等于ex的结束逻辑块地址ee_block + ee_len
    else if (((map->m_lblk + map_len) == (ee_block + ee_len)) &&
		   (map_len < ee_len) &&	/*L1*///要求映射的物理块数map_len要小于ex已经映射的物理块数ee_len
		   ex < EXT_LAST_EXTENT(eh)) {	/*L2*///ex是指向叶子节点ext4_extent_header后的ext4_extent，不是最后一个
		/* See if we can merge right */
		ext4_lblk_t next_lblk;
		ext4_fsblk_t next_pblk, ee_pblk;
		unsigned int next_len;

        //abut_ex指向ex下一个struct ext4_extent结构
		abut_ex = ex + 1;
        //下一个struct ext4_extent结构代表的起始逻辑块地址
		next_lblk = le32_to_cpu(abut_ex->ee_block);
        //下一个struct ext4_extent结构映射的物理块个数
		next_len = ext4_ext_get_actual_len(abut_ex);
        //下一个struct ext4_extent结构代表的起始物理块地址
		next_pblk = ext4_ext_pblock(abut_ex);
        //ex这个struct ext4_extent结构代表的起始物理块地址
		ee_pblk = ext4_ext_pblock(ex);

		/*
		 * A transfer of blocks from 'ex' to 'abut_ex' is allowed
		 * upon those conditions:
		 * - C1: abut_ex is initialized,
		 * - C2: abut_ex is logically abutting ex,
		 * - C3: abut_ex is physically abutting ex,
		 * - C4: abut_ex can receive the additional blocks without
		 *   overflowing the (initialized) length limit.
		 */
		 
		/*ex和它后边的abut_ex逻辑块地址紧挨着，即ex结束逻辑块地址等于abut的起始逻辑块地址，
         并且要求映射的物理块数map_len要小于ex已经映射的物理块数ee_len等等。把ex的
         (ex->ee_block + ee_len - map_len)~(ex->ee_block + ee_len)这map_len个逻辑块合并到
         abut_ex。合并后abut_ex的逻辑块范围是(ex->ee_block + ee_len - map_len)~
         (next_lblk+next_len),ex的逻辑块范围缩小为ex->ee_block~(ee_len - map_len)*/
		if ((!ext4_ext_is_uninitialized(abut_ex)) &&/*C1*///abut_ex必须是初始化状态
             //abut_ex的逻辑块地址和物理块地址与ex的紧挨着,abut_ex在ex后边
            ((map->m_lblk + map_len) == next_lblk) &&/*C2*/
		    ((ee_pblk + ee_len) == next_pblk) &&		/*C3*/
		    //abut_ex和ex的映射的物理块个数总和小于0x8000，一个ext4_extent结构最大映射的物理块个数不能超过0x8000
		    (next_len < (EXT_INIT_MAX_LEN - map_len))) {	/*C4*/
			err = ext4_ext_get_access(handle, inode, path + depth);
			if (err)
				goto out;

			trace_ext4_ext_convert_to_initialized_fastpath(inode,
				map, ex, abut_ex);

			/* Shift the start of abut_ex by 'map_len' blocks */
            //下边这是把ex的逻辑块范围(ex->ee_block + ee_len - map_len)~(ex->ee_block + ee_len)
            //这map_len个逻辑块合并到后边的abut_ex，合并后abut_ex的逻辑块范围是
            //(ex->ee_block + ee_len - map_len)~(next_lblk+next_len),ex的逻辑块范围缩小为
            //ex->ee_block~ee_len - map_len
			abut_ex->ee_block = cpu_to_le32(next_lblk - map_len);
			ext4_ext_store_pblock(abut_ex, next_pblk - map_len);//设置新的物理块首地址
            //ex映射的逻辑块范围只剩下ex->ee_block~(ex->ee_block + ee_len - map_len)
            ex->ee_len = cpu_to_le16(ee_len - map_len);
            /*标记ex为"uninitialized"状态,这是重点，ex还是未初始化状态*/
			ext4_ext_mark_uninitialized(ex); /* Restore the flag */

			/* Extend abut_ex by 'map_len' blocks */
            //abut_ex逻辑块个数增大到(next_len + map_len)个
			abut_ex->ee_len = cpu_to_le16(next_len + map_len);

			/* Result: number of initialized blocks past m_lblk */
            //abut_ex逻辑块个数增加了map+len个
			allocated = map_len;
		}
	}

    /*执行到这里，有两种可能。本次要映射的逻辑块范围map->m_lblk ~ (map->m_lblk+map->m_len)在ex(即path[depth].p_ext指向的ext4_extent)
    的逻辑块范围内，即在ee_block~(ee_block + ee_len)范围内。并且，map->m_lblk==ee_block~或者map->m_lblk+map->m_len==ee_block + ee_len，
    即map的逻辑块范围在ex的逻辑块范围最开头或者最结尾。
    最后，如果ex与它前后或者后边ext4_extent(即abut_ex)的逻辑块地址紧挨着。以上条件都满足时，则把ex逻辑块范围内的本次要映射的逻辑块
    map->m_len个逻辑块合并到abut_ex。因为本次要映射的逻辑块的起始逻辑块地址map->m_lblk或者计数逻辑块地址map->m_lblk+map->m_len与
    abut_ex的结束逻辑块地址或起始逻辑块地址紧挨着。如此，相当于把本次要映射的逻辑块map->m_lblk ~ (map->m_lblk+map->m_len)从ex剥离掉
    ，全合并到abut_ex，合并map->m_len个逻辑块。为什么要这样操作?因为abut_ex是标记已初始化状态的，ex是为初始化状态，而映射的逻辑块
    范围map->m_lblk ~ (map->m_lblk+map->m_len)又在ex的最开头或者最结尾，把它合并到abut_ex就完工了，后续就可以给ext4 extent tree使用了。
    最后，ex依然被标记未初始化状态。如果map合并到abut_ex map->m_len个逻辑块，则allocated=map->m_len，直接goto out退出该函数。
    如果没有发生合并，则allocated = ee_len - (map->m_lblk - ee_block)=(ee_len+ee_block) - map->m_lblk，即map->m_lblk到ex结束逻辑块
    地址(ee_block + ee_len)之间的逻辑块数。后续执行ext4_split_extent()对ex的逻辑块范围进程分割。*/
    if (allocated) {//allocated非0说明abut_ex逻辑块范围吞并了ex map_len个逻辑块
		/* Mark the block containing both extents as dirty */
        //ext4_extent映射的逻辑块范围可能发生变化了，标记对应的物理块映射的bh或者文件inode脏.
		ext4_ext_dirty(handle, inode, path + depth);

		/* Update path to point to the right extent */
        //ext4 extent叶子节点变为abut_ex，原来的ex废弃了
		path[depth].p_ext = abut_ex;
        
		goto out;//退出该函数
	} else
	    //如果abut_ex没有吞并ex的逻辑块，allocated是map->m_lblk到ex结束逻辑块地址之间的逻辑块数
		allocated = ee_len - (map->m_lblk - ee_block);//allocated=(ee_len+ee_block) - map->m_lblk

	WARN_ON(map->m_lblk < ee_block);
	/*
	 * It is safe to convert extent to initialized via explicit
	 * zeroout only if extent is fully insde i_size or new_size.
	 */
	split_flag |= ee_block + ee_len <= eof_block ? EXT4_EXT_MAY_ZEROOUT : 0;

	if (EXT4_EXT_MAY_ZEROOUT & split_flag)
		max_zeroout = sbi->s_extent_max_zeroout_kb >>
			(inode->i_sb->s_blocksize_bits - 10);

	/* If extent is less than s_max_zeroout_kb, zeroout directly */
	if (max_zeroout && (ee_len <= max_zeroout)) {//测试一般不成立
		err = ext4_ext_zeroout(inode, ex);
		if (err)
			goto out;
        //把ex逻辑块信息复制给zero_ex，zero_ex啥用?
		zero_ex.ee_block = ex->ee_block;
		zero_ex.ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex));
		ext4_ext_store_pblock(&zero_ex, ext4_ext_pblock(ex));

		err = ext4_ext_get_access(handle, inode, path + depth);
		if (err)
			goto out;
        //ex标记"initialized"状态
		ext4_ext_mark_initialized(ex);
		ext4_ext_try_to_merge(handle, inode, path, ex);
		err = ext4_ext_dirty(handle, inode, path + path->p_depth);
		goto out;
	}

	/*
	 * four cases:
	 * 1. split the extent into three extents.
	 * 2. split the extent into two extents, zeroout the first half.
	 * 3. split the extent into two extents, zeroout the second half.
	 * 4. split the extent into two extents with out zeroout.
	 */
	split_map.m_lblk = map->m_lblk;
	split_map.m_len = map->m_len;

	if (max_zeroout && (allocated > map->m_len)) {//测试一般不成立
		if (allocated <= max_zeroout) {
			/* case 3 */
			zero_ex.ee_block =
					 cpu_to_le32(map->m_lblk);
			zero_ex.ee_len = cpu_to_le16(allocated);
			ext4_ext_store_pblock(&zero_ex,
				ext4_ext_pblock(ex) + map->m_lblk - ee_block);
			err = ext4_ext_zeroout(inode, &zero_ex);
			if (err)
				goto out;
			split_map.m_lblk = map->m_lblk;
			split_map.m_len = allocated;
		} else if (map->m_lblk - ee_block + map->m_len < max_zeroout) {
			/* case 2 */
			if (map->m_lblk != ee_block) {
				zero_ex.ee_block = ex->ee_block;
				zero_ex.ee_len = cpu_to_le16(map->m_lblk -
							ee_block);
				ext4_ext_store_pblock(&zero_ex,
						      ext4_ext_pblock(ex));
				err = ext4_ext_zeroout(inode, &zero_ex);
				if (err)
					goto out;
			}

			split_map.m_lblk = ee_block;
			split_map.m_len = map->m_lblk - ee_block + map->m_len;
			allocated = map->m_len;
		}
	}
    /*在这里，map->m_lblk大于ex的起始逻辑块地址ee_block是可以保证的。即map的起始逻辑块地址map->m_lblk肯定在ex的逻辑块范围内。
      现在执行ext4_split_extent()把ex的逻辑块范围ee_block~(ee_block + ee_len)进行分割，分割情况有几种
    1:如果 map->m_lblk +map->m_len 小于ee_block + ee_len，即map的结束逻辑块地址小于ex的结束逻辑块地址。则把ex的逻辑块范围分割成3段
     ee_block~map->m_lblk 和 map->m_lblk~(map->m_lblk +map->m_len) 和 (map->m_lblk +map->m_len)~(ee_block + ee_len)。这种情况，就能
     保证本次要求映射的map->m_len个逻辑块都能完成映射，即allocated =map->m_len。
    2:如果 map->m_lblk +map->m_len 大于等于ee_block + ee_len，即map的结束逻辑块地址大于ex的结束逻辑块地址。则把ex的逻辑块范围分割成2段
     ee_block~map->m_lblk 和 map->m_lblk~(ee_block + ee_len)，这种情况，不能保证本次要求映射的map->m_len个逻辑块都完成映射。只能映射
     (ee_block + ee_len) - map->m_lblk个逻辑块，即allocated =(ee_block + ee_len) - map->m_lblk。
    */
	allocated = ext4_split_extent(handle, inode, path,
				      &split_map, split_flag, flags);
	if (allocated < 0)
		err = allocated;

out:
	/* If we have gotten a failure, don't zero out status tree */
	if (!err)
		err = ext4_es_zeroout(inode, &zero_ex);
	return err ? err : allocated;
}

/*
 * This function is called by ext4_ext_map_blocks() from
 * ext4_get_blocks_dio_write() when DIO to write
 * to an uninitialized extent.
 *
 * Writing to an uninitialized extent may result in splitting the uninitialized
 * extent into multiple initialized/uninitialized extents (up to three)
 * There are three possibilities:
 *   a> There is no split required: Entire extent should be uninitialized
 *   b> Splits in two extents: Write is happening at either end of the extent
 *   c> Splits in three extents: Somone is writing in middle of the extent
 *
 * One of more index blocks maybe needed if the extent tree grow after
 * the uninitialized extent split. To prevent ENOSPC occur at the IO
 * complete, we need to split the uninitialized extent before DIO submit
 * the IO. The uninitialized extent called at this time will be split
 * into three uninitialized extent(at most). After IO complete, the part
 * being filled will be convert to initialized by the end_io callback function
 * via ext4_convert_unwritten_extents().
 *
 * Returns the size of uninitialized extent to be written on success.
 */
static int ext4_split_unwritten_extents(handle_t *handle,
					struct inode *inode,
					struct ext4_map_blocks *map,
					struct ext4_ext_path *path,
					int flags)
{
	ext4_lblk_t eof_block;
	ext4_lblk_t ee_block;
	struct ext4_extent *ex;
	unsigned int ee_len;
	int split_flag = 0, depth;

	ext_debug("ext4_split_unwritten_extents: inode %lu, logical"
		"block %llu, max_blocks %u\n", inode->i_ino,
		(unsigned long long)map->m_lblk, map->m_len);

	eof_block = (inode->i_size + inode->i_sb->s_blocksize - 1) >>
		inode->i_sb->s_blocksize_bits;
	if (eof_block < map->m_lblk + map->m_len)
		eof_block = map->m_lblk + map->m_len;
	/*
	 * It is safe to convert extent to initialized via explicit
	 * zeroout only if extent is fully insde i_size or new_size.
	 */
	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);

	split_flag |= ee_block + ee_len <= eof_block ? EXT4_EXT_MAY_ZEROOUT : 0;
	split_flag |= EXT4_EXT_MARK_UNINIT2;
	if (flags & EXT4_GET_BLOCKS_CONVERT)
		split_flag |= EXT4_EXT_DATA_VALID2;
	flags |= EXT4_GET_BLOCKS_PRE_IO;
	return ext4_split_extent(handle, inode, path, map, split_flag, flags);
}

static int ext4_convert_unwritten_extents_endio(handle_t *handle,
						struct inode *inode,
						struct ext4_map_blocks *map,
						struct ext4_ext_path *path)
{
	struct ext4_extent *ex;
	ext4_lblk_t ee_block;
	unsigned int ee_len;
	int depth;
	int err = 0;

	depth = ext_depth(inode);
    //ex指向起始逻辑块地址最接近map->m_lblk这个起始逻辑块地址的ext4_extent
	ex = path[depth].p_ext;
    //ext4_extent结构代表的起始逻辑块地址
	ee_block = le32_to_cpu(ex->ee_block);
    //ext4_extent结构代表的映射的物理块个数
	ee_len = ext4_ext_get_actual_len(ex);

	ext_debug("ext4_convert_unwritten_extents_endio: inode %lu, logical"
		"block %llu, max_blocks %u\n", inode->i_ino,
		  (unsigned long long)ee_block, ee_len);

	/* If extent is larger than requested it is a clear sign that we still
	 * have some extent state machine issues left. So extent_split is still
	 * required.
	 * TODO: Once all related issues will be fixed this situation should be
	 * illegal.
	 */
	if (ee_block != map->m_lblk || ee_len > map->m_len) {
#ifdef EXT4_DEBUG
		ext4_warning("Inode (%ld) finished: extent logical block %llu,"
			     " len %u; IO logical block %llu, len %u\n",
			     inode->i_ino, (unsigned long long)ee_block, ee_len,
			     (unsigned long long)map->m_lblk, map->m_len);
#endif
		err = ext4_split_unwritten_extents(handle, inode, map, path,
						   EXT4_GET_BLOCKS_CONVERT);
		if (err < 0)
			goto out;
		ext4_ext_drop_refs(path);
		path = ext4_ext_find_extent(inode, map->m_lblk, path);
		if (IS_ERR(path)) {
			err = PTR_ERR(path);
			goto out;
		}
		depth = ext_depth(inode);
		ex = path[depth].p_ext;
	}

	err = ext4_ext_get_access(handle, inode, path + depth);
	if (err)
		goto out;
	/* first mark the extent as initialized */
	ext4_ext_mark_initialized(ex);

	/* note: ext4_ext_correct_indexes() isn't needed here because
	 * borders are not changed
	 */
	ext4_ext_try_to_merge(handle, inode, path, ex);

	/* Mark modified extent as dirty */
	err = ext4_ext_dirty(handle, inode, path + path->p_depth);
out:
	ext4_ext_show_leaf(inode, path);
	return err;
}

static void unmap_underlying_metadata_blocks(struct block_device *bdev,
			sector_t block, int count)
{
	int i;
	for (i = 0; i < count; i++)
                unmap_underlying_metadata(bdev, block + i);
}

/*
 * Handle EOFBLOCKS_FL flag, clearing it if necessary
 */
static int check_eofblocks_fl(handle_t *handle, struct inode *inode,
			      ext4_lblk_t lblk,
			      struct ext4_ext_path *path,
			      unsigned int len)
{
	int i, depth;
	struct ext4_extent_header *eh;
	struct ext4_extent *last_ex;

	if (!ext4_test_inode_flag(inode, EXT4_INODE_EOFBLOCKS))
		return 0;

	depth = ext_depth(inode);
	eh = path[depth].p_hdr;

	/*
	 * We're going to remove EOFBLOCKS_FL entirely in future so we
	 * do not care for this case anymore. Simply remove the flag
	 * if there are no extents.
	 */
	if (unlikely(!eh->eh_entries))
		goto out;
	last_ex = EXT_LAST_EXTENT(eh);
	/*
	 * We should clear the EOFBLOCKS_FL flag if we are writing the
	 * last block in the last extent in the file.  We test this by
	 * first checking to see if the caller to
	 * ext4_ext_get_blocks() was interested in the last block (or
	 * a block beyond the last block) in the current extent.  If
	 * this turns out to be false, we can bail out from this
	 * function immediately.
	 */
	if (lblk + len < le32_to_cpu(last_ex->ee_block) +
	    ext4_ext_get_actual_len(last_ex))
		return 0;
	/*
	 * If the caller does appear to be planning to write at or
	 * beyond the end of the current extent, we then test to see
	 * if the current extent is the last extent in the file, by
	 * checking to make sure it was reached via the rightmost node
	 * at each level of the tree.
	 */
	for (i = depth-1; i >= 0; i--)
		if (path[i].p_idx != EXT_LAST_INDEX(path[i].p_hdr))
			return 0;
out:
	ext4_clear_inode_flag(inode, EXT4_INODE_EOFBLOCKS);
	return ext4_mark_inode_dirty(handle, inode);
}

/**
 * ext4_find_delalloc_range: find delayed allocated block in the given range.
 *
 * Return 1 if there is a delalloc block in the range, otherwise 0.
 */
int ext4_find_delalloc_range(struct inode *inode,
			     ext4_lblk_t lblk_start,
			     ext4_lblk_t lblk_end)
{
	struct extent_status es;

	ext4_es_find_delayed_extent_range(inode, lblk_start, lblk_end, &es);
	if (es.es_len == 0)
		return 0; /* there is no delay extent in this tree */
	else if (es.es_lblk <= lblk_start &&
		 lblk_start < es.es_lblk + es.es_len)
		return 1;
	else if (lblk_start <= es.es_lblk && es.es_lblk <= lblk_end)
		return 1;
	else
		return 0;
}

int ext4_find_delalloc_cluster(struct inode *inode, ext4_lblk_t lblk)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	ext4_lblk_t lblk_start, lblk_end;
	lblk_start = EXT4_LBLK_CMASK(sbi, lblk);
	lblk_end = lblk_start + sbi->s_cluster_ratio - 1;

	return ext4_find_delalloc_range(inode, lblk_start, lblk_end);
}

/**
 * Determines how many complete clusters (out of those specified by the 'map')
 * are under delalloc and were reserved quota for.
 * This function is called when we are writing out the blocks that were
 * originally written with their allocation delayed, but then the space was
 * allocated using fallocate() before the delayed allocation could be resolved.
 * The cases to look for are:
 * ('=' indicated delayed allocated blocks
 *  '-' indicates non-delayed allocated blocks)
 * (a) partial clusters towards beginning and/or end outside of allocated range
 *     are not delalloc'ed.
 *	Ex:
 *	|----c---=|====c====|====c====|===-c----|
 *	         |++++++ allocated ++++++|
 *	==> 4 complete clusters in above example
 *
 * (b) partial cluster (outside of allocated range) towards either end is
 *     marked for delayed allocation. In this case, we will exclude that
 *     cluster.
 *	Ex:
 *	|----====c========|========c========|
 *	     |++++++ allocated ++++++|
 *	==> 1 complete clusters in above example
 *
 *	Ex:
 *	|================c================|
 *            |++++++ allocated ++++++|
 *	==> 0 complete clusters in above example
 *
 * The ext4_da_update_reserve_space will be called only if we
 * determine here that there were some "entire" clusters that span
 * this 'allocated' range.
 * In the non-bigalloc case, this function will just end up returning num_blks
 * without ever calling ext4_find_delalloc_range.
 */
static unsigned int
get_reserved_cluster_alloc(struct inode *inode, ext4_lblk_t lblk_start,
			   unsigned int num_blks)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	ext4_lblk_t alloc_cluster_start, alloc_cluster_end;
	ext4_lblk_t lblk_from, lblk_to, c_offset;
	unsigned int allocated_clusters = 0;

	alloc_cluster_start = EXT4_B2C(sbi, lblk_start);
	alloc_cluster_end = EXT4_B2C(sbi, lblk_start + num_blks - 1);

	/* max possible clusters for this allocation */
	allocated_clusters = alloc_cluster_end - alloc_cluster_start + 1;

	trace_ext4_get_reserved_cluster_alloc(inode, lblk_start, num_blks);

	/* Check towards left side */
	c_offset = EXT4_LBLK_COFF(sbi, lblk_start);
	if (c_offset) {
		lblk_from = EXT4_LBLK_CMASK(sbi, lblk_start);
		lblk_to = lblk_from + c_offset - 1;

		if (ext4_find_delalloc_range(inode, lblk_from, lblk_to))
			allocated_clusters--;
	}

	/* Now check towards right. */
	c_offset = EXT4_LBLK_COFF(sbi, lblk_start + num_blks);
	if (allocated_clusters && c_offset) {
		lblk_from = lblk_start + num_blks;
		lblk_to = lblk_from + (sbi->s_cluster_ratio - c_offset) - 1;

		if (ext4_find_delalloc_range(inode, lblk_from, lblk_to))
			allocated_clusters--;
	}

	return allocated_clusters;
}

static int
ext4_ext_handle_uninitialized_extents(handle_t *handle, struct inode *inode,
			struct ext4_map_blocks *map,
			struct ext4_ext_path *path, int flags,
			unsigned int allocated, ext4_fsblk_t newblock)
{
	int ret = 0;
	int err = 0;
	ext4_io_end_t *io = ext4_inode_aio(inode);

	ext_debug("ext4_ext_handle_uninitialized_extents: inode %lu, logical "
		  "block %llu, max_blocks %u, flags %x, allocated %u\n",
		  inode->i_ino, (unsigned long long)map->m_lblk, map->m_len,
		  flags, allocated);
	ext4_ext_show_leaf(inode, path);

	/*
	 * When writing into uninitialized space, we should not fail to
	 * allocate metadata blocks for the new extent block if needed.
	 */
	flags |= EXT4_GET_BLOCKS_METADATA_NOFAIL;

	trace_ext4_ext_handle_uninitialized_extents(inode, map, flags,
						    allocated, newblock);

	/* get_block() before submit the IO, split the extent */
    //这个if在direct IO模式才成立
	if ((flags & EXT4_GET_BLOCKS_PRE_IO/*0x0008*/)) {
		ret = ext4_split_unwritten_extents(handle, inode, map,
						   path, flags);
		if (ret <= 0)
			goto out;
		/*
		 * Flag the inode(non aio case) or end_io struct (aio case)
		 * that this IO needs to conversion to written when IO is
		 * completed
		 */
		if (io)
			ext4_set_io_unwritten_flag(inode, io);
		else
			ext4_set_inode_state(inode, EXT4_STATE_DIO_UNWRITTEN);
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		if (ext4_should_dioread_nolock(inode))
			map->m_flags |= EXT4_MAP_UNINIT;
		goto out;
	}

    
	/* IO end_io complete, convert the filled extent to written */
    //这个貌似是DIO模式，IO传输完成回调函数end_io()时执行到的
	if ((flags & EXT4_GET_BLOCKS_CONVERT/*0x0010*/)) {
		ret = ext4_convert_unwritten_extents_endio(handle, inode, map,
							path);
		if (ret >= 0) {
			ext4_update_inode_fsync_trans(handle, inode, 1);
			err = check_eofblocks_fl(handle, inode, map->m_lblk,
						 path, map->m_len);
		} else
			err = ret;
		map->m_flags |= EXT4_MAP_MAPPED;
		if (allocated > map->m_len)
			allocated = map->m_len;
		map->m_len = allocated;
		goto out2;
	}
    
	/* buffered IO case 一般的文件读写走这里*/
	/*
	 * repeat fallocate creation request
	 * we already have an unwritten extent
	 */
	if (flags & EXT4_GET_BLOCKS_UNINIT_EXT/*0x0002*/) {
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		goto map_out;
	}

	/* buffered READ or buffered write_begin() lookup */
    //这个分支看着像是第一次读写文件，ext4
	if ((flags & EXT4_GET_BLOCKS_CREATE/*0x0001*/) == 0) {
		/*
		 * We have blocks reserved already.  We
		 * return allocated blocks so that delalloc
		 * won't do block reservation for us.  But
		 * the buffer head will be unmapped so that
		 * a read from the block returns 0s.
		 */
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		goto out1;
	}

	/* buffered write, writepage time, convert*/
    //正常执行到这里
	ret = ext4_ext_convert_to_initialized(handle, inode, map, path, flags);
	if (ret >= 0)
		ext4_update_inode_fsync_trans(handle, inode, 1);
out:
	if (ret <= 0) {
		err = ret;
		goto out2;
	} else
		allocated = ret;
	map->m_flags |= EXT4_MAP_NEW;
	/*
	 * if we allocated more blocks than requested
	 * we need to make sure we unmap the extra block
	 * allocated. The actual needed block will get
	 * unmapped later when we find the buffer_head marked
	 * new.
	 */
	if (allocated > map->m_len) {
		unmap_underlying_metadata_blocks(inode->i_sb->s_bdev,
					newblock + map->m_len,
					allocated - map->m_len);
		allocated = map->m_len;
	}
	map->m_len = allocated;

	/*
	 * If we have done fallocate with the offset that is already
	 * delayed allocated, we would have block reservation
	 * and quota reservation done in the delayed write path.
	 * But fallocate would have already updated quota and block
	 * count for this offset. So cancel these reservation
	 */
	if (flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE) {
		unsigned int reserved_clusters;
		reserved_clusters = get_reserved_cluster_alloc(inode,
				map->m_lblk, map->m_len);
		if (reserved_clusters)
			ext4_da_update_reserve_space(inode,
						     reserved_clusters,
						     0);
	}

map_out:
	map->m_flags |= EXT4_MAP_MAPPED;
	if ((flags & EXT4_GET_BLOCKS_KEEP_SIZE/*0x0080*/) == 0) {
		err = check_eofblocks_fl(handle, inode, map->m_lblk, path,
					 map->m_len);
		if (err < 0)
			goto out2;
	}
out1:
	if (allocated > map->m_len)
		allocated = map->m_len;
	ext4_ext_show_leaf(inode, path);
	map->m_pblk = newblock;
	map->m_len = allocated;
out2:
	if (path) {
		ext4_ext_drop_refs(path);
		kfree(path);
	}
	return err ? err : allocated;
}

/*
 * get_implied_cluster_alloc - check to see if the requested
 * allocation (in the map structure) overlaps with a cluster already
 * allocated in an extent.
 *	@sb	The filesystem superblock structure
 *	@map	The requested lblk->pblk mapping
 *	@ex	The extent structure which might contain an implied
 *			cluster allocation
 *
 * This function is called by ext4_ext_map_blocks() after we failed to
 * find blocks that were already in the inode's extent tree.  Hence,
 * we know that the beginning of the requested region cannot overlap
 * the extent from the inode's extent tree.  There are three cases we
 * want to catch.  The first is this case:
 *
 *		 |--- cluster # N--|
 *    |--- extent ---|	|---- requested region ---|
 *			|==========|
 *
 * The second case that we need to test for is this one:
 *
 *   |--------- cluster # N ----------------|
 *	   |--- requested region --|   |------- extent ----|
 *	   |=======================|
 *
 * The third case is when the requested region lies between two extents
 * within the same cluster:
 *          |------------- cluster # N-------------|
 * |----- ex -----|                  |---- ex_right ----|
 *                  |------ requested region ------|
 *                  |================|
 *
 * In each of the above cases, we need to set the map->m_pblk and
 * map->m_len so it corresponds to the return the extent labelled as
 * "|====|" from cluster #N, since it is already in use for data in
 * cluster EXT4_B2C(sbi, map->m_lblk).	We will then return 1 to
 * signal to ext4_ext_map_blocks() that map->m_pblk should be treated
 * as a new "allocated" block region.  Otherwise, we will return 0 and
 * ext4_ext_map_blocks() will then allocate one or more new clusters
 * by calling ext4_mb_new_blocks().
 */
static int get_implied_cluster_alloc(struct super_block *sb,
				     struct ext4_map_blocks *map,
				     struct ext4_extent *ex,
				     struct ext4_ext_path *path)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_lblk_t c_offset = EXT4_LBLK_COFF(sbi, map->m_lblk);
	ext4_lblk_t ex_cluster_start, ex_cluster_end;
	ext4_lblk_t rr_cluster_start;
	ext4_lblk_t ee_block = le32_to_cpu(ex->ee_block);
	ext4_fsblk_t ee_start = ext4_ext_pblock(ex);
	unsigned short ee_len = ext4_ext_get_actual_len(ex);

	/* The extent passed in that we are trying to match */
	ex_cluster_start = EXT4_B2C(sbi, ee_block);
	ex_cluster_end = EXT4_B2C(sbi, ee_block + ee_len - 1);

	/* The requested region passed into ext4_map_blocks() */
	rr_cluster_start = EXT4_B2C(sbi, map->m_lblk);

	if ((rr_cluster_start == ex_cluster_end) ||
	    (rr_cluster_start == ex_cluster_start)) {
		if (rr_cluster_start == ex_cluster_end)
			ee_start += ee_len - 1;
		map->m_pblk = EXT4_PBLK_CMASK(sbi, ee_start) + c_offset;
		map->m_len = min(map->m_len,
				 (unsigned) sbi->s_cluster_ratio - c_offset);
		/*
		 * Check for and handle this case:
		 *
		 *   |--------- cluster # N-------------|
		 *		       |------- extent ----|
		 *	   |--- requested region ---|
		 *	   |===========|
		 */

		if (map->m_lblk < ee_block)
			map->m_len = min(map->m_len, ee_block - map->m_lblk);

		/*
		 * Check for the case where there is already another allocated
		 * block to the right of 'ex' but before the end of the cluster.
		 *
		 *          |------------- cluster # N-------------|
		 * |----- ex -----|                  |---- ex_right ----|
		 *                  |------ requested region ------|
		 *                  |================|
		 */
		if (map->m_lblk > ee_block) {
			ext4_lblk_t next = ext4_ext_next_allocated_block(path);
			map->m_len = min(map->m_len, next - map->m_lblk);
		}

		trace_ext4_get_implied_cluster_alloc_exit(sb, map, 1);
		return 1;
	}

	trace_ext4_get_implied_cluster_alloc_exit(sb, map, 0);
	return 0;
}


/*
 * Block allocation/map/preallocation routine for extents based files
 *
 *
 * Need to be called with
 * down_read(&EXT4_I(inode)->i_data_sem) if not allocating file system block
 * (ie, create is zero). Otherwise down_write(&EXT4_I(inode)->i_data_sem)
 *
 * return > 0, number of of blocks already mapped/allocated
 *          if create == 0 and these are pre-allocated blocks
 *          	buffer head is unmapped
 *          otherwise blocks are mapped
 *
 * return = 0, if plain look up failed (blocks have not been allocated)
 *          buffer head is unmapped
 *
 * return < 0, error case.
 */
int ext4_ext_map_blocks(handle_t *handle, struct inode *inode,
			struct ext4_map_blocks *map, int flags)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent newex, *ex, *ex2;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	ext4_fsblk_t newblock = 0;
	int free_on_err = 0, err = 0, depth, ret;
	unsigned int allocated = 0, offset = 0;
	unsigned int allocated_clusters = 0;
	struct ext4_allocation_request ar;
	ext4_io_end_t *io = ext4_inode_aio(inode);
	ext4_lblk_t cluster_offset;
	int set_unwritten = 0;

	ext_debug("blocks %u/%u requested for inode %lu\n",
		  map->m_lblk, map->m_len, inode->i_ino);
	trace_ext4_ext_map_blocks_enter(inode, map->m_lblk, map->m_len, flags);

	/* find extent for this block */

/*根据ext4 extent B+树的根节点，先找到每一层索引节点中最接近传入的起始逻辑块地址map->m_lblk
 的ext4_extent_idx保存到path[ppos]->p_idx.然后找到最后一层的叶子节点中最接近传入的
 起始逻辑块地址map->m_lblk的ext4_extent，保存到path[ppos]->p_ext。这个ext4_extent才包含了逻辑块地址和物理块地址的映射关系。*/
	path = ext4_ext_find_extent(inode, map->m_lblk, NULL);
	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		path = NULL;
		goto out2;
	}
    //ext4 extent B+树深度
	depth = ext_depth(inode);

	/*
	 * consistent leaf must not be empty;
	 * this situation is possible, though, _during_ tree modification;
	 * this is why assert can't be put in ext4_ext_find_extent()
	 */
	if (unlikely(path[depth].p_ext == NULL && depth != 0)) {
		EXT4_ERROR_INODE(inode, "bad extent address "
				 "lblock: %lu, depth: %d pblock %lld",
				 (unsigned long) map->m_lblk, depth,
				 path[depth].p_block);
		err = -EIO;
		goto out2;
	}
    //指向起始逻辑块地址最接近map->m_lblk这个起始逻辑块地址的ext4_extent
	ex = path[depth].p_ext;
	if (ex) {
        //ext4_extent结构代表的起始逻辑块地址
		ext4_lblk_t ee_block = le32_to_cpu(ex->ee_block);
        //ext4_extent结构代表的起始物理块地址
		ext4_fsblk_t ee_start = ext4_ext_pblock(ex);
		unsigned short ee_len;

		/*
		 * Uninitialized extents are treated as holes, except that
		 * we split out initialized portions during a write.
		 */
		//ext4_extent结构代表的映射的物理块个数
		ee_len = ext4_ext_get_actual_len(ex);

		trace_ext4_ext_show_extent(inode, ee_block, ee_start, ee_len);

		/* if found extent covers block, simply return it */
        //如果map->m_lblk在ex代表的起始逻辑块地址范围内，奇怪，为什么只是map->m_lblk，没有map->m_lblk+m_len呢?map->m_lblk~map->m_lblk+
        //m_len才是本次要映射的逻辑块地址范围呀，这点在后续的函数会判断。注意，并不能保证map->m_lblk就在ex代表的起始逻辑块地址范围内，
        //因为map->m_lblk会非常大，map->m_lblk > ee_block + ee_len。此时只能在下边基于map->m_lblk创建一个新的ext4_extent结构，插入ext4_extent B+树
		if (in_range(map->m_lblk, ee_block, ee_len)) {
            //newblock : map->m_lblk这个起始逻辑块地址对应的物理块地址
			newblock = map->m_lblk - ee_block + ee_start;
			/* number of remaining blocks in the extent */
            //allocated : map->m_lblk到(ext4_extent->ee_block+ext4_extent->ee_len)这个范围的block个数
            //ext4_extent->ee_block+ext4_extent->ee_len是ext4_extent结构的结束逻辑块地址
            allocated = ee_len - (map->m_lblk - ee_block);
			ext_debug("%u fit into %u:%d -> %llu\n", map->m_lblk,
				  ee_block, ee_len, newblock);
            
            //ex已经初始化过直接goto out返回，否则执行下边的ext4_ext_handle_uninitialized_extents()
			if (!ext4_ext_is_uninitialized(ex))
				goto out;
            
            /*注意，这里有个隐藏点，ex是未初始化状态才会在这里执行ext4_ext_handle_uninitialized_extents()*/
			ret = ext4_ext_handle_uninitialized_extents(//高版本内核改名称为ext4_ext_handle_unwritten_extents()
				handle, inode, map, path, flags,
				allocated, newblock);
			if (ret < 0)
				err = ret;
			else
				allocated = ret;
			goto out3;
		}
	}

	if ((sbi->s_cluster_ratio > 1) &&
	    ext4_find_delalloc_cluster(inode, map->m_lblk))
		map->m_flags |= EXT4_MAP_FROM_CLUSTER;

	/*
	 * requested block isn't allocated yet;
	 * we couldn't try to create block if create flag is zero
	 */
	if ((flags & EXT4_GET_BLOCKS_CREATE) == 0) {
		/*
		 * put just found gap into cache to speed up
		 * subsequent requests
		 */
		if ((flags & EXT4_GET_BLOCKS_NO_PUT_HOLE) == 0)
			ext4_ext_put_gap_in_cache(inode, path, map->m_lblk);
		goto out2;
	}

	/*
	 * Okay, we need to do block allocation.
	 */
	map->m_flags &= ~EXT4_MAP_FROM_CLUSTER;
    //设置newex的起始逻辑块号，newex是针对本次映射分配的ext4_extent结构
	newex.ee_block = cpu_to_le32(map->m_lblk);
	cluster_offset = EXT4_LBLK_COFF(sbi, map->m_lblk);

	/*
	 * If we are doing bigalloc, check to see if the extent returned
	 * by ext4_ext_find_extent() implies a cluster we can use.
	 */
	if (cluster_offset && ex &&
	    get_implied_cluster_alloc(inode->i_sb, map, ex, path)) {
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		map->m_flags |= EXT4_MAP_FROM_CLUSTER;
		goto got_allocated_blocks;
	}

	/* find neighbour allocated blocks */
	ar.lleft = map->m_lblk;
    //ar.lleft = le32_to_cpu(ex->ee_block) + ee_len - 1
	err = ext4_ext_search_left(inode, path, &ar.lleft, &ar.pleft);//ar.lleft影响到下边ext4_mb_new_blocks()分配映射的物理块
	if (err)
		goto out2;
	ar.lright = map->m_lblk;
	ex2 = NULL;
//path[depth].p_ext不是叶子节点最后一个ext4_extent结构，则找到path[depth].p_ext后边的ext4_extent结构给ex2，ex2的起始逻辑块地址赋于
//ar.lright 。否则，选择ext4 extent B+最左边的索引节点下的叶子节点的第一个ext4_extent结构给ex2，ex2的起始逻辑块地址赋于ar.lright
	err = ext4_ext_search_right(inode, path, &ar.lright, &ar.pright, &ex2);//ar.lright影响到下边ext4_mb_new_blocks()分配映射的物理块
	if (err)
		goto out2;

	/* Check if the extent after searching to the right implies a
	 * cluster we can use. */
	//sbi->s_cluster_ratio=1
	if ((sbi->s_cluster_ratio > 1) && ex2 &&
	    get_implied_cluster_alloc(inode->i_sb, map, ex2, path)) {//不成立
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		map->m_flags |= EXT4_MAP_FROM_CLUSTER;
		goto got_allocated_blocks;
	}

	/*
	 * See if request is beyond maximum number of blocks we can have in
	 * a single extent. For an initialized extent this limit is
	 * EXT_INIT_MAX_LEN and for an uninitialized extent this limit is
	 * EXT_UNINIT_MAX_LEN.
	 */
	if (map->m_len > EXT_INIT_MAX_LEN &&
	    !(flags & EXT4_GET_BLOCKS_UNINIT_EXT))//不成立
		map->m_len = EXT_INIT_MAX_LEN;
	else if (map->m_len > EXT_UNINIT_MAX_LEN &&
		 (flags & EXT4_GET_BLOCKS_UNINIT_EXT))//不成立
		map->m_len = EXT_UNINIT_MAX_LEN;

	/* Check if we can really insert (m_lblk)::(m_lblk + m_len) extent */
	newex.ee_len = cpu_to_le16(map->m_len);
	err = ext4_ext_check_overlap(sbi, inode, &newex, path);
	if (err)
		allocated = ext4_ext_get_actual_len(&newex);
	else
		allocated = map->m_len;

	/* allocate new block */
	ar.inode = inode;
    //找到map->m_lblk映射的物理块地址并返回给ar.goal
	ar.goal = ext4_ext_find_goal(inode, path, map->m_lblk);
    //ar.logical是逻辑块地址
	ar.logical = map->m_lblk;
	/*
	 * We calculate the offset from the beginning of the cluster
	 * for the logical block number, since when we allocate a
	 * physical cluster, the physical block should start at the
	 * same offset from the beginning of the cluster.  This is
	 * needed so that future calls to get_implied_cluster_alloc()
	 * work correctly.
	 */
	offset = EXT4_LBLK_COFF(sbi, map->m_lblk);//offset测试时0
	ar.len = EXT4_NUM_B2C(sbi, offset+allocated);
	ar.goal -= offset;
	ar.logical -= offset;
	if (S_ISREG(inode->i_mode))
		ar.flags = EXT4_MB_HINT_DATA;
	else
		/* disable in-core preallocation for non-regular files */
		ar.flags = 0;
	if (flags & EXT4_GET_BLOCKS_NO_NORMALIZE)
		ar.flags |= EXT4_MB_HINT_NOPREALLOC;
    //分配一个物理块，4K大小，这就是为ext4 extent B+树叶子结点分配的，返回物理块号。测试结果 newblock 和 ar.goal有时相等，有时不相等。
    //本次映射的起始逻辑块地址是map->m_lblk，映射物理块个数map->m_len，ext4_mb_new_blocks()除了要找到newblock这个起始逻辑块地址，还得
    //保证找到newblock打头的连续map->m_len个物理块，必须是连续的，这才是更重要的。
	newblock = ext4_mb_new_blocks(handle, &ar, &err);
	if (!newblock)
		goto out2;
	ext_debug("allocate new block: goal %llu, found %llu/%u\n",
		  ar.goal, newblock, allocated);
	free_on_err = 1;
	allocated_clusters = ar.len;
	ar.len = EXT4_C2B(sbi, ar.len) - offset;
	if (ar.len > allocated)
		ar.len = allocated;

got_allocated_blocks:
	/* try to insert new extent into found leaf and return */
    //设置newex映射的起始物理块号，newex是针对本次映射分配的ext4_extent结构
	ext4_ext_store_pblock(&newex, newblock + offset);//offset是0
	//设置newex映射的物理块个数
	newex.ee_len = cpu_to_le16(ar.len);
	/* Mark uninitialized */
	if (flags & EXT4_GET_BLOCKS_UNINIT_EXT){
		ext4_ext_mark_uninitialized(&newex);
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		/*
		 * io_end structure was created for every IO write to an
		 * uninitialized extent. To avoid unnecessary conversion,
		 * here we flag the IO that really needs the conversion.
		 * For non asycn direct IO case, flag the inode state
		 * that we need to perform conversion when IO is done.
		 */
		if ((flags & EXT4_GET_BLOCKS_PRE_IO))
			set_unwritten = 1;
		if (ext4_should_dioread_nolock(inode))
			map->m_flags |= EXT4_MAP_UNINIT;
	}

	err = 0;
	if ((flags & EXT4_GET_BLOCKS_KEEP_SIZE) == 0)//成立
		err = check_eofblocks_fl(handle, inode, map->m_lblk,
					 path, ar.len);
    
	if (!err)//把newex这个插入ext4 extent B+树
		err = ext4_ext_insert_extent(handle, inode, path,
					     &newex, flags);

	if (!err && set_unwritten) {
		if (io)
			ext4_set_io_unwritten_flag(inode, io);
		else
			ext4_set_inode_state(inode,
					     EXT4_STATE_DIO_UNWRITTEN);
	}

	if (err && free_on_err) {
		int fb_flags = flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE ?
			EXT4_FREE_BLOCKS_NO_QUOT_UPDATE : 0;
		/* free data blocks we just allocated */
		/* not a good idea to call discard here directly,
		 * but otherwise we'd need to call it every free() */
		ext4_discard_preallocations(inode);
		ext4_free_blocks(handle, inode, NULL, ext4_ext_pblock(&newex),
				 ext4_ext_get_actual_len(&newex), fb_flags);
		goto out2;
	}

	/* previous routine could use block we allocated */
	newblock = ext4_ext_pblock(&newex);
	allocated = ext4_ext_get_actual_len(&newex);
	if (allocated > map->m_len)
		allocated = map->m_len;
	map->m_flags |= EXT4_MAP_NEW;

	/*
	 * Update reserved blocks/metadata blocks after successful
	 * block allocation which had been deferred till now.
	 */
	if (flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE) {
		unsigned int reserved_clusters;
		/*
		 * Check how many clusters we had reserved this allocated range
		 */
		reserved_clusters = get_reserved_cluster_alloc(inode,
						map->m_lblk, allocated);
		if (map->m_flags & EXT4_MAP_FROM_CLUSTER) {
			if (reserved_clusters) {
				/*
				 * We have clusters reserved for this range.
				 * But since we are not doing actual allocation
				 * and are simply using blocks from previously
				 * allocated cluster, we should release the
				 * reservation and not claim quota.
				 */
				ext4_da_update_reserve_space(inode,
						reserved_clusters, 0);
			}
		} else {
			BUG_ON(allocated_clusters < reserved_clusters);
			if (reserved_clusters < allocated_clusters) {
				struct ext4_inode_info *ei = EXT4_I(inode);
				int reservation = allocated_clusters -
						  reserved_clusters;
				/*
				 * It seems we claimed few clusters outside of
				 * the range of this allocation. We should give
				 * it back to the reservation pool. This can
				 * happen in the following case:
				 *
				 * * Suppose s_cluster_ratio is 4 (i.e., each
				 *   cluster has 4 blocks. Thus, the clusters
				 *   are [0-3],[4-7],[8-11]...
				 * * First comes delayed allocation write for
				 *   logical blocks 10 & 11. Since there were no
				 *   previous delayed allocated blocks in the
				 *   range [8-11], we would reserve 1 cluster
				 *   for this write.
				 * * Next comes write for logical blocks 3 to 8.
				 *   In this case, we will reserve 2 clusters
				 *   (for [0-3] and [4-7]; and not for [8-11] as
				 *   that range has a delayed allocated blocks.
				 *   Thus total reserved clusters now becomes 3.
				 * * Now, during the delayed allocation writeout
				 *   time, we will first write blocks [3-8] and
				 *   allocate 3 clusters for writing these
				 *   blocks. Also, we would claim all these
				 *   three clusters above.
				 * * Now when we come here to writeout the
				 *   blocks [10-11], we would expect to claim
				 *   the reservation of 1 cluster we had made
				 *   (and we would claim it since there are no
				 *   more delayed allocated blocks in the range
				 *   [8-11]. But our reserved cluster count had
				 *   already gone to 0.
				 *
				 *   Thus, at the step 4 above when we determine
				 *   that there are still some unwritten delayed
				 *   allocated blocks outside of our current
				 *   block range, we should increment the
				 *   reserved clusters count so that when the
				 *   remaining blocks finally gets written, we
				 *   could claim them.
				 */
				dquot_reserve_block(inode,
						EXT4_C2B(sbi, reservation));
				spin_lock(&ei->i_block_reservation_lock);
				ei->i_reserved_data_blocks += reservation;
				spin_unlock(&ei->i_block_reservation_lock);
			}
			/*
			 * We will claim quota for all newly allocated blocks.
			 * We're updating the reserved space *after* the
			 * correction above so we do not accidentally free
			 * all the metadata reservation because we might
			 * actually need it later on.
			 */
			ext4_da_update_reserve_space(inode, allocated_clusters,
							1);
		}
	}

	/*
	 * Cache the extent and update transaction to commit on fdatasync only
	 * when it is _not_ an uninitialized extent.
	 */
	if ((flags & EXT4_GET_BLOCKS_UNINIT_EXT) == 0)
		ext4_update_inode_fsync_trans(handle, inode, 1);
	else
		ext4_update_inode_fsync_trans(handle, inode, 0);
out:
	if (allocated > map->m_len)
		allocated = map->m_len;
	ext4_ext_show_leaf(inode, path);
	map->m_flags |= EXT4_MAP_MAPPED;
    //本次映射的起始逻辑块地址对应的起始物理块号
	map->m_pblk = newblock;
    //本次完成映射的物理块数，并不能保证allocated等于map->m_len，还有可能小于
	map->m_len = allocated;
out2:
	if (path) {
		ext4_ext_drop_refs(path);
		kfree(path);
	}

out3:
	trace_ext4_ext_map_blocks_exit(inode, map, err ? err : allocated);

	return err ? err : allocated;
}

void ext4_ext_truncate(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	ext4_lblk_t last_block;
	int err = 0;

	/*
	 * TODO: optimization is possible here.
	 * Probably we need not scan at all,
	 * because page truncation is enough.
	 */

	/* we have to know where to truncate from in crash case */
	EXT4_I(inode)->i_disksize = inode->i_size;
	ext4_mark_inode_dirty(handle, inode);

	last_block = (inode->i_size + sb->s_blocksize - 1)
			>> EXT4_BLOCK_SIZE_BITS(sb);
retry:
	err = ext4_es_remove_extent(inode, last_block,
				    EXT_MAX_BLOCKS - last_block);
	if (err == -ENOMEM) {
		cond_resched();
		congestion_wait(BLK_RW_ASYNC, HZ/50);
		goto retry;
	}
	if (err) {
		ext4_std_error(inode->i_sb, err);
		return;
	}
	err = ext4_ext_remove_space(inode, last_block, EXT_MAX_BLOCKS - 1);
	ext4_std_error(inode->i_sb, err);
}

static void ext4_falloc_update_inode(struct inode *inode,
				int mode, loff_t new_size, int update_ctime)
{
	struct timespec now;

	if (update_ctime) {
		now = current_fs_time(inode->i_sb);
		if (!timespec_equal(&inode->i_ctime, &now))
			inode->i_ctime = now;
	}
	/*
	 * Update only when preallocation was requested beyond
	 * the file size.
	 */
	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
		if (new_size > i_size_read(inode))
			i_size_write(inode, new_size);
		if (new_size > EXT4_I(inode)->i_disksize)
			ext4_update_i_disksize(inode, new_size);
	} else {
		/*
		 * Mark that we allocate beyond EOF so the subsequent truncate
		 * can proceed even if the new size is the same as i_size.
		 */
		if (new_size > i_size_read(inode))
			ext4_set_inode_flag(inode, EXT4_INODE_EOFBLOCKS);
	}

}

/*
 * preallocate space for a file. This implements ext4's fallocate file
 * operation, which gets called from sys_fallocate system call.
 * For block-mapped files, posix_fallocate should fall back to the method
 * of writing zeroes to the required new blocks (the same behavior which is
 * expected for file systems which do not support fallocate() system call).
 */
long ext4_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	handle_t *handle;
	loff_t new_size;
	unsigned int max_blocks;
	int ret = 0;
	int ret2 = 0;
	int retries = 0;
	int flags;
	struct ext4_map_blocks map;
	unsigned int credits, blkbits = inode->i_blkbits;

	/* Return error if mode is not supported */
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	if (mode & FALLOC_FL_PUNCH_HOLE)
		return ext4_punch_hole(file, offset, len);

	ret = ext4_convert_inline_data(inode);
	if (ret)
		return ret;

	/*
	 * currently supporting (pre)allocate mode for extent-based
	 * files _only_
	 */
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)))
		return -EOPNOTSUPP;

	trace_ext4_fallocate_enter(inode, offset, len, mode);
	map.m_lblk = offset >> blkbits;
	/*
	 * We can't just convert len to max_blocks because
	 * If blocksize = 4096 offset = 3072 and len = 2048
	 */
	max_blocks = (EXT4_BLOCK_ALIGN(len + offset, blkbits) >> blkbits)
		- map.m_lblk;
	/*
	 * credits to insert 1 extent into extent tree
	 */
	credits = ext4_chunk_trans_blocks(inode, max_blocks);
	mutex_lock(&inode->i_mutex);
	ret = inode_newsize_ok(inode, (len + offset));
	if (ret) {
		mutex_unlock(&inode->i_mutex);
		trace_ext4_fallocate_exit(inode, offset, max_blocks, ret);
		return ret;
	}
	flags = EXT4_GET_BLOCKS_CREATE_UNINIT_EXT;
	if (mode & FALLOC_FL_KEEP_SIZE)
		flags |= EXT4_GET_BLOCKS_KEEP_SIZE;
	/*
	 * Don't normalize the request if it can fit in one extent so
	 * that it doesn't get unnecessarily split into multiple
	 * extents.
	 */
	if (len <= EXT_UNINIT_MAX_LEN << blkbits)
		flags |= EXT4_GET_BLOCKS_NO_NORMALIZE;

retry:
	while (ret >= 0 && ret < max_blocks) {
		map.m_lblk = map.m_lblk + ret;
		map.m_len = max_blocks = max_blocks - ret;
		handle = ext4_journal_start(inode, EXT4_HT_MAP_BLOCKS,
					    credits);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			break;
		}
		ret = ext4_map_blocks(handle, inode, &map, flags);
		if (ret <= 0) {
#ifdef EXT4FS_DEBUG
			ext4_warning(inode->i_sb,
				     "inode #%lu: block %u: len %u: "
				     "ext4_ext_map_blocks returned %d",
				     inode->i_ino, map.m_lblk,
				     map.m_len, ret);
#endif
			ext4_mark_inode_dirty(handle, inode);
			ret2 = ext4_journal_stop(handle);
			break;
		}
		if ((map.m_lblk + ret) >= (EXT4_BLOCK_ALIGN(offset + len,
						blkbits) >> blkbits))
			new_size = offset + len;
		else
			new_size = ((loff_t) map.m_lblk + ret) << blkbits;

		ext4_falloc_update_inode(inode, mode, new_size,
					 (map.m_flags & EXT4_MAP_NEW));
		ext4_mark_inode_dirty(handle, inode);
		if ((file->f_flags & O_SYNC) && ret >= max_blocks)
			ext4_handle_sync(handle);
		ret2 = ext4_journal_stop(handle);
		if (ret2)
			break;
	}
	if (ret == -ENOSPC &&
			ext4_should_retry_alloc(inode->i_sb, &retries)) {
		ret = 0;
		goto retry;
	}
	mutex_unlock(&inode->i_mutex);
	trace_ext4_fallocate_exit(inode, offset, max_blocks,
				ret > 0 ? ret2 : ret);
	return ret > 0 ? ret2 : ret;
}

/*
 * This function convert a range of blocks to written extents
 * The caller of this function will pass the start offset and the size.
 * all unwritten extents within this range will be converted to
 * written extents.
 *
 * This function is called from the direct IO end io call back
 * function, to convert the fallocated extents after IO is completed.
 * Returns 0 on success.
 */
int ext4_convert_unwritten_extents(struct inode *inode, loff_t offset,
				    ssize_t len)
{
	handle_t *handle;
	unsigned int max_blocks;
	int ret = 0;
	int ret2 = 0;
	struct ext4_map_blocks map;
	unsigned int credits, blkbits = inode->i_blkbits;

	map.m_lblk = offset >> blkbits;
	/*
	 * We can't just convert len to max_blocks because
	 * If blocksize = 4096 offset = 3072 and len = 2048
	 */
	max_blocks = ((EXT4_BLOCK_ALIGN(len + offset, blkbits) >> blkbits) -
		      map.m_lblk);
	/*
	 * credits to insert 1 extent into extent tree
	 */
	credits = ext4_chunk_trans_blocks(inode, max_blocks);
	while (ret >= 0 && ret < max_blocks) {
		map.m_lblk += ret;
		map.m_len = (max_blocks -= ret);
		handle = ext4_journal_start(inode, EXT4_HT_MAP_BLOCKS, credits);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			break;
		}
		ret = ext4_map_blocks(handle, inode, &map,
				      EXT4_GET_BLOCKS_IO_CONVERT_EXT);
		if (ret <= 0)
			ext4_warning(inode->i_sb,
				     "inode #%lu: block %u: len %u: "
				     "ext4_ext_map_blocks returned %d",
				     inode->i_ino, map.m_lblk,
				     map.m_len, ret);
		ext4_mark_inode_dirty(handle, inode);
		ret2 = ext4_journal_stop(handle);
		if (ret <= 0 || ret2 )
			break;
	}
	return ret > 0 ? ret2 : ret;
}

/*
 * If newes is not existing extent (newes->ec_pblk equals zero) find
 * delayed extent at start of newes and update newes accordingly and
 * return start of the next delayed extent.
 *
 * If newes is existing extent (newes->ec_pblk is not equal zero)
 * return start of next delayed extent or EXT_MAX_BLOCKS if no delayed
 * extent found. Leave newes unmodified.
 */
static int ext4_find_delayed_extent(struct inode *inode,
				    struct extent_status *newes)
{
	struct extent_status es;
	ext4_lblk_t block, next_del;

	if (newes->es_pblk == 0) {
		ext4_es_find_delayed_extent_range(inode, newes->es_lblk,
				newes->es_lblk + newes->es_len - 1, &es);

		/*
		 * No extent in extent-tree contains block @newes->es_pblk,
		 * then the block may stay in 1)a hole or 2)delayed-extent.
		 */
		if (es.es_len == 0)
			/* A hole found. */
			return 0;

		if (es.es_lblk > newes->es_lblk) {
			/* A hole found. */
			newes->es_len = min(es.es_lblk - newes->es_lblk,
					    newes->es_len);
			return 0;
		}

		newes->es_len = es.es_lblk + es.es_len - newes->es_lblk;
	}

	block = newes->es_lblk + newes->es_len;
	ext4_es_find_delayed_extent_range(inode, block, EXT_MAX_BLOCKS, &es);
	if (es.es_len == 0)
		next_del = EXT_MAX_BLOCKS;
	else
		next_del = es.es_lblk;

	return next_del;
}
/* fiemap flags we can handle specified here */
#define EXT4_FIEMAP_FLAGS	(FIEMAP_FLAG_SYNC|FIEMAP_FLAG_XATTR)

static int ext4_xattr_fiemap(struct inode *inode,
				struct fiemap_extent_info *fieinfo)
{
	__u64 physical = 0;
	__u64 length;
	__u32 flags = FIEMAP_EXTENT_LAST;
	int blockbits = inode->i_sb->s_blocksize_bits;
	int error = 0;

	/* in-inode? */
	if (ext4_test_inode_state(inode, EXT4_STATE_XATTR)) {
		struct ext4_iloc iloc;
		int offset;	/* offset of xattr in inode */

		error = ext4_get_inode_loc(inode, &iloc);
		if (error)
			return error;
		physical = (__u64)iloc.bh->b_blocknr << blockbits;
		offset = EXT4_GOOD_OLD_INODE_SIZE +
				EXT4_I(inode)->i_extra_isize;
		physical += offset;
		length = EXT4_SB(inode->i_sb)->s_inode_size - offset;
		flags |= FIEMAP_EXTENT_DATA_INLINE;
		brelse(iloc.bh);
	} else { /* external block */
		physical = (__u64)EXT4_I(inode)->i_file_acl << blockbits;
		length = inode->i_sb->s_blocksize;
	}

	if (physical)
		error = fiemap_fill_next_extent(fieinfo, 0, physical,
						length, flags);
	return (error < 0 ? error : 0);
}

int ext4_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		__u64 start, __u64 len)
{
	ext4_lblk_t start_blk;
	int error = 0;

	if (ext4_has_inline_data(inode)) {
		int has_inline = 1;

		error = ext4_inline_data_fiemap(inode, fieinfo, &has_inline);

		if (has_inline)
			return error;
	}

	/* fallback to generic here if not in extents fmt */
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)))
		return generic_block_fiemap(inode, fieinfo, start, len,
			ext4_get_block);

	if (fiemap_check_flags(fieinfo, EXT4_FIEMAP_FLAGS))
		return -EBADR;

	if (fieinfo->fi_flags & FIEMAP_FLAG_XATTR) {
		error = ext4_xattr_fiemap(inode, fieinfo);
	} else {
		ext4_lblk_t len_blks;
		__u64 last_blk;

		start_blk = start >> inode->i_sb->s_blocksize_bits;
		last_blk = (start + len - 1) >> inode->i_sb->s_blocksize_bits;
		if (last_blk >= EXT_MAX_BLOCKS)
			last_blk = EXT_MAX_BLOCKS-1;
		len_blks = ((ext4_lblk_t) last_blk) - start_blk + 1;

		/*
		 * Walk the extent tree gathering extent information
		 * and pushing extents back to the user.
		 */
		error = ext4_fill_fiemap_extents(inode, start_blk,
						 len_blks, fieinfo);
	}

	return error;
}
