/*
 * Copyright (c) 2003-2006, Cluster File Systems, Inc, info@clusterfs.com
 * Written by Alex Tomas <alex@clusterfs.com>
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

#ifndef _EXT4_EXTENTS
#define _EXT4_EXTENTS

#include "ext4.h"

/*
 * With AGGRESSIVE_TEST defined, the capacity of index/leaf blocks
 * becomes very small, so index split, in-depth growing and
 * other hard changes happen much more often.
 * This is for debug purposes only.
 */
#define AGGRESSIVE_TEST_

/*
 * With EXTENTS_STATS defined, the number of blocks and extents
 * are collected in the truncate path. They'll be shown at
 * umount time.
 */
#define EXTENTS_STATS__

/*
 * If CHECK_BINSEARCH is defined, then the results of the binary search
 * will also be checked by linear search.
 */
#define CHECK_BINSEARCH__

/*
 * If EXT_STATS is defined then stats numbers are collected.
 * These number will be displayed at umount time.
 */
#define EXT_STATS_


/*
 * ext4_inode has i_block array (60 bytes total).
 * The first 12 bytes store ext4_extent_header;
 * the remainder stores an array of ext4_extent.
 * For non-inode extent blocks, ext4_extent_tail
 * follows the array.
 */

/*
 * This is the extent tail on-disk structure.
 * All other extent structures are 12 bytes long.  It turns out that
 * block_size % 12 >= 4 for at least all powers of 2 greater than 512, which
 * covers all valid ext4 block sizes.  Therefore, this tail structure can be
 * crammed into the end of the block without having to rebalance the tree.
 */
struct ext4_extent_tail {
	__le32	et_checksum;	/* crc32c(uuid+inum+extent_block) */
};

/*
 * This is the extent on-disk structure.
 * It's used at the bottom of the tree.
 */
//ext4 extent B+树叶子节点的ext4_extent，真正包含逻辑块地址和物理块地址的映射关系
//ext4 extent B+树叶子节点上的ext4_extent是按照其起始逻辑块地址从小到大、从左到右顺序排列的
struct ext4_extent {
    //起始逻辑块地址
	__le32	ee_block;	/* first logical block extent covers */
    //映射的block个数
	__le16	ee_len;		/* number of blocks covered by extent */
    //由ee_start_hi和ee_start_lo一起计算出起始逻辑块地址映射的起始物理块地址
	__le16	ee_start_hi;	/* high 16 bits of physical block */
	__le32	ee_start_lo;	/* low 32 bits of physical block */
};

/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
//ext4 extent B+树的索引节点
/*重点，ext4_extent_idx没有类似ext4_extent结构的成员ee_len，ext4_extent_idx只有起始逻辑块号呀*/
struct ext4_extent_idx {
    //起始逻辑块地址
	__le32	ei_block;	/* index covers logical blocks from 'block' */
    //由ei_leaf_lo和ei_leaf_hi一起计算出物理块号，这个物理块保存下层叶子节点或者索引节点4K数据。没错，索引节点ext4_extent_idx结构
    //的ei_leaf_lo和ei_leaf_hi保存了下层索引节点或者叶子节点的物理块号，索引节点的ext4_extent_idx通过其ei_leaf_lo和ei_leaf_hi成员
    //指向下层的索引节点或者叶子节点。这点非常重要
	__le32	ei_leaf_lo;	/* pointer to the physical block of the next *
				 * level. leaf or next index could be there */
	__le16	ei_leaf_hi;	/* high 16 bits of physical block */
	__u16	ei_unused;
};

/*
 * Each block (leaves and indexes), even inode-stored has header.
 */
//ext4 extent索引节点或叶子节点头结构体信息
struct ext4_extent_header {
	__le16	eh_magic;	/* probably will support different formats */
	__le16	eh_entries;	/* number of valid entries */
	__le16	eh_max;		/* capacity of store in entries */
    //当前叶子结点或者索引节点所处ext4 extent B+树层数。B+树的根节点的eh_depth是B+树的真正深度，叶子结点的eh_depth是0，
    //B+树根节点下方的索引节点的eh_depth是1，其他类推。ext4_ext_grow_indepth()中加1。
	__le16	eh_depth;	/* has tree real underlying blocks? */
	__le32	eh_generation;	/* generation of the tree */
};

#define EXT4_EXT_MAGIC		cpu_to_le16(0xf30a)

#define EXT4_EXTENT_TAIL_OFFSET(hdr) \
	(sizeof(struct ext4_extent_header) + \
	 (sizeof(struct ext4_extent) * le16_to_cpu((hdr)->eh_max)))

static inline struct ext4_extent_tail *
find_ext4_extent_tail(struct ext4_extent_header *eh)
{
	return (struct ext4_extent_tail *)(((void *)eh) +
					   EXT4_EXTENT_TAIL_OFFSET(eh));
}

/*
 * Array of ext4_ext_path contains path to some extent.
 * Creation/lookup routines use it for traversal/splitting/etc.
 * Truncate uses it to simulate recursive walking.
 */
//根据一个逻辑块地址找到它所属于的ext4 ext4_extent B+树索引节点和叶子节点信息，
//保存到ext4_ext_path
struct ext4_ext_path {
    //ext4_ext_find_extent()中赋值，是索引节点时，是由ext4_extent_idx结构的ei_leaf_lo和ei_leaf_hi成员计算出的物理块号，这个物理块保存
    //了下层叶子节点或者索引节点4K数据。是叶子节点时，是由ext4_extent结构的ee_start_hi和ee_start_lo成员计算出的物理块号，
    //这个物理块号是ext4_extent的逻辑块地址映射的的起始物理块号
	ext4_fsblk_t			p_block;
	//当前索引节点或者叶子节点处于ext4 extent B+树第几层。ext4 extent B+树没有索引节点或者叶子节点时，层数是0，有一层叶子节点时层数是1
	//再加一层索引节点时层数是2
	__u16				p_depth;
	//ext4_ext_binsearch()中赋值，指向起始逻辑块地址最接近传入的起始逻辑块地址map->m_lblk的ext4_extent
	struct ext4_extent		*p_ext;
    //ext4_ext_binsearch_idx()中赋值，指向起始逻辑块地址最接近传入的起始逻辑块地址map->m_lblk的ext4_extent_idx
	struct ext4_extent_idx		*p_idx;
    //指向ext4 extent B+索引节点和叶子节点的头结点结构体,ext4_ext_find_extent()中赋值
	struct ext4_extent_header	*p_hdr;
    //ext4 extent B+索引节点或者叶子节点的N个ext4_extent_idx或N个ext4_extent结构是保存在物理块的，物理块号就是p_block
    //p_bh就指向这个物理块映射的buffer_head，通过p_bh就可以访问到ext4 extent B+索引节点或者叶子节点的ext4_extent_idx或ext4_extent结构
	struct buffer_head		*p_bh;
};

/*
 * structure for external API
 */

/*
 * Maximum number of logical blocks in a file; ext4_extent's ee_block is
 * __le32.
 */
#define EXT_MAX_BLOCKS	0xffffffff//0x8000-1

/*
 * EXT_INIT_MAX_LEN is the maximum number of blocks we can have in an
 * initialized extent. This is 2^15 and not (2^16 - 1), since we use the
 * MSB of ee_len field in the extent datastructure to signify if this
 * particular extent is an initialized extent or an uninitialized (i.e.
 * preallocated).
 * EXT_UNINIT_MAX_LEN is the maximum number of blocks we can have in an
 * uninitialized extent.
 * If ee_len is <= 0x8000, it is an initialized extent. Otherwise, it is an
 * uninitialized one. In other words, if MSB of ee_len is set, it is an
 * uninitialized extent with only one special scenario when ee_len = 0x8000.
 * In this case we can not have an uninitialized extent of zero length and
 * thus we make it as a special case of initialized extent with 0x8000 length.
 * This way we get better extent-to-group alignment for initialized extents.
 * Hence, the maximum number of blocks we can have in an *initialized*
 * extent is 2^15 (32768) and in an *uninitialized* extent is 2^15-1 (32767).
 */
#define EXT_INIT_MAX_LEN	(1UL << 15)
#define EXT_UNINIT_MAX_LEN	(EXT_INIT_MAX_LEN - 1)

//ext4 extent B+树叶子节点第一个ext4_extent结构内存地址，不一定有ext4_extent结构
#define EXT_FIRST_EXTENT(__hdr__) \
	((struct ext4_extent *) (((char *) (__hdr__)) +		\
				 sizeof(struct ext4_extent_header)))
#define EXT_FIRST_INDEX(__hdr__) \
	((struct ext4_extent_idx *) (((char *) (__hdr__)) +	\
				     sizeof(struct ext4_extent_header)))
//ext4 extent B+树索引节点或者叶子节点的ext4_extent_idx或ext4_extent个数小于eh_max返回1
#define EXT_HAS_FREE_INDEX(__path__) \
	(le16_to_cpu((__path__)->p_hdr->eh_entries) \
				     < le16_to_cpu((__path__)->p_hdr->eh_max))
//ext4 extent B+树叶子节点有效的最后一个ext4_extent结构内存地址，注意是有效的，不一定是叶子节点最后一个ext4_extent
#define EXT_LAST_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
//ext4 extent B+树索引节点有效的最后一个ext4_extent_idx结构内存地址，注意是有效的，不一定是索引节点最后一个ext4_extent_idx
#define EXT_LAST_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
//ext4 extent B+树最大最靠后的ext4_extent结构，eh_max大于eh_entries
#define EXT_MAX_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)
//ext4 extent B+树最大最靠后的ext4_extent_idx结构
#define EXT_MAX_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)

static inline struct ext4_extent_header *ext_inode_hdr(struct inode *inode)
{
	return (struct ext4_extent_header *) EXT4_I(inode)->i_data;
}

static inline struct ext4_extent_header *ext_block_hdr(struct buffer_head *bh)
{
	return (struct ext4_extent_header *) bh->b_data;
}
//这是根据EXT4_I(inode)->i_data，得到root 节点ext4_extent_header->eh_depth，计算ext4 extent B+树深度
static inline unsigned short ext_depth(struct inode *inode)
{
	return le16_to_cpu(ext_inode_hdr(inode)->eh_depth);
}
//ext4_ext_convert_to_initialized()中多处标记ext4_extent的未初始化状态
static inline void ext4_ext_mark_uninitialized(struct ext4_extent *ext)
{
	/* We can not have an uninitialized extent of zero length! */
	BUG_ON((le16_to_cpu(ext->ee_len) & ~EXT_INIT_MAX_LEN) == 0);
    //设置ext4_extent的uninitialized标记，无非是设置bit15为1
	ext->ee_len |= cpu_to_le16(EXT_INIT_MAX_LEN);
}

static inline int ext4_ext_is_uninitialized(struct ext4_extent *ext)
{
	/* Extent with ee_len of 0x8000 is treated as an initialized extent */
    //ext->ee_len大于0x8000，说明ext4_extent是没有初始化过的
	return (le16_to_cpu(ext->ee_len) > EXT_INIT_MAX_LEN);
}
//ext4_extent结构映射的物理块个数
static inline int ext4_ext_get_actual_len(struct ext4_extent *ext)
{
	return (le16_to_cpu(ext->ee_len) <= EXT_INIT_MAX_LEN ?
		le16_to_cpu(ext->ee_len) :
		(le16_to_cpu(ext->ee_len) - EXT_INIT_MAX_LEN));
}

static inline void ext4_ext_mark_initialized(struct ext4_extent *ext)
{
	ext->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ext));
}

/*
 * ext4_ext_pblock:
 * combine low and high parts of physical block number into ext4_fsblk_t
 */
static inline ext4_fsblk_t ext4_ext_pblock(struct ext4_extent *ex)
{
	ext4_fsblk_t block;

	block = le32_to_cpu(ex->ee_start_lo);
	block |= ((ext4_fsblk_t) le16_to_cpu(ex->ee_start_hi) << 31) << 1;
	return block;
}

/*
 * ext4_idx_pblock:
 * combine low and high parts of a leaf physical block number into ext4_fsblk_t
 */
static inline ext4_fsblk_t ext4_idx_pblock(struct ext4_extent_idx *ix)
{
	ext4_fsblk_t block;

	block = le32_to_cpu(ix->ei_leaf_lo);
	block |= ((ext4_fsblk_t) le16_to_cpu(ix->ei_leaf_hi) << 31) << 1;
	return block;
}

/*
 * ext4_ext_store_pblock:
 * stores a large physical block number into an extent struct,
 * breaking it into parts
 */
static inline void ext4_ext_store_pblock(struct ext4_extent *ex,
					 ext4_fsblk_t pb)
{
	ex->ee_start_lo = cpu_to_le32((unsigned long) (pb & 0xffffffff));
	ex->ee_start_hi = cpu_to_le16((unsigned long) ((pb >> 31) >> 1) &
				      0xffff);
}

/*
 * ext4_idx_store_pblock:
 * stores a large physical block number into an index struct,
 * breaking it into parts
 */
static inline void ext4_idx_store_pblock(struct ext4_extent_idx *ix,
					 ext4_fsblk_t pb)
{
	ix->ei_leaf_lo = cpu_to_le32((unsigned long) (pb & 0xffffffff));
	ix->ei_leaf_hi = cpu_to_le16((unsigned long) ((pb >> 31) >> 1) &
				     0xffff);
}
//ext4_extent映射的逻辑块范围可能发生变化了，标记对应的物理块映射的bh或者文件inode脏.
#define ext4_ext_dirty(handle, inode, path) \
		__ext4_ext_dirty(__func__, __LINE__, (handle), (inode), (path))
int __ext4_ext_dirty(const char *where, unsigned int line, handle_t *handle,
		     struct inode *inode, struct ext4_ext_path *path);

#endif /* _EXT4_EXTENTS */

