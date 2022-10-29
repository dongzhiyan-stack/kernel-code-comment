/*
 *  linux/fs/ext4/ialloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  BSD ufs-inspired inode and directory allocation by
 *  Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <asm/byteorder.h>

#include "ext4.h"
#include "ext4_jbd2.h"
#include "xattr.h"
#include "acl.h"

#include <trace/events/ext4.h>

/*
 * ialloc.c contains the inodes allocation and deallocation routines
 */

/*
 * The free inodes are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.
 */

/*
 * To avoid calling the atomic setbit hundreds or thousands of times, we only
 * need to use it within a single byte (to ensure we get endianness right).
 * We can use memset for the rest of the bitmap as there are no other users.
 */
void ext4_mark_bitmap_end(int start_bit, int end_bit, char *bitmap)
{
	int i;

	if (start_bit >= end_bit)
		return;

	ext4_debug("mark end bits +%d through +%d used\n", start_bit, end_bit);
	for (i = start_bit; i < ((start_bit + 7) & ~7UL); i++)
		ext4_set_bit(i, bitmap);
	if (i < end_bit)
		memset(bitmap + (i >> 3), 0xff, (end_bit - i) >> 3);
}

/* Initializes an uninitialized inode bitmap */
static unsigned ext4_init_inode_bitmap(struct super_block *sb,
				       struct buffer_head *bh,
				       ext4_group_t block_group,
				       struct ext4_group_desc *gdp)
{
	J_ASSERT_BH(bh, buffer_locked(bh));

	/* If checksum is bad mark all blocks and inodes use to prevent
	 * allocation, essentially implementing a per-group read-only flag. */
	if (!ext4_group_desc_csum_verify(sb, block_group, gdp)) {
		ext4_error(sb, "Checksum bad for group %u", block_group);
		ext4_free_group_clusters_set(sb, gdp, 0);
		ext4_free_inodes_set(sb, gdp, 0);
		ext4_itable_unused_set(sb, gdp, 0);
		memset(bh->b_data, 0xff, sb->s_blocksize);
		ext4_inode_bitmap_csum_set(sb, block_group, gdp, bh,
					   EXT4_INODES_PER_GROUP(sb) / 8);
		return 0;
	}

	memset(bh->b_data, 0, (EXT4_INODES_PER_GROUP(sb) + 7) / 8);
	ext4_mark_bitmap_end(EXT4_INODES_PER_GROUP(sb), sb->s_blocksize * 8,
			bh->b_data);
	ext4_inode_bitmap_csum_set(sb, block_group, gdp, bh,
				   EXT4_INODES_PER_GROUP(sb) / 8);
	ext4_group_desc_csum_set(sb, block_group, gdp);

	return EXT4_INODES_PER_GROUP(sb);
}

void ext4_end_bitmap_read(struct buffer_head *bh, int uptodate)
{
	if (uptodate) {
		set_buffer_uptodate(bh);
		set_bitmap_uptodate(bh);
	}
	unlock_buffer(bh);
	put_bh(bh);
}

/*
 * Read the inode allocation bitmap for a given block_group, reading
 * into the specified slot in the superblock's bitmap cache.
 *
 * Return buffer_head of bitmap on success or NULL.
 */
//先根据块组号block_group得到块组描述符ext4_group_desc，再由块组描述符得到保存
//inode bitmap数据的物理块号，最后读取该inode bitmap物理块的数据到bh并返回
static struct buffer_head *
ext4_read_inode_bitmap(struct super_block *sb, ext4_group_t block_group)
{
	struct ext4_group_desc *desc;
	struct buffer_head *bh = NULL;
	ext4_fsblk_t bitmap_blk;
    //根据块组号block_group得到它对应的块组描述符ext4_group_desc
	desc = ext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return NULL;
    
    //该函数只是返回这个块组的inode bitmap的物理块号bitmap_blk，这个物理块保存了inode bitmap的数据
	bitmap_blk = ext4_inode_bitmap(sb, desc);
    //根据inode bitmap的物理块号得到映射的bh
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ext4_error(sb, "Cannot read inode bitmap - "
			    "block_group = %u, inode_bitmap = %llu",
			    block_group, bitmap_blk);
		return NULL;
	}
    //如果inode bitmap物理块的数据已经读取到了映射的bh，直接返回bh。否则下边执行
    //submit_bh()读取该物理块数据到bh
	if (bitmap_uptodate(bh))
		goto verify;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}

	ext4_lock_group(sb, block_group);
	if (desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)) {
		ext4_init_inode_bitmap(sb, bh, block_group, desc);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		set_buffer_verified(bh);
		ext4_unlock_group(sb, block_group);
		unlock_buffer(bh);
		return bh;
	}
	ext4_unlock_group(sb, block_group);

	if (buffer_uptodate(bh)) {
		/*
		 * if not uninit if bh is uptodate,
		 * bitmap is also uptodate
		 */
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		goto verify;
	}
	/*
	 * submit the buffer_head for reading
	 */
	trace_ext4_load_inode_bitmap(sb, block_group);
	bh->b_end_io = ext4_end_bitmap_read;
	get_bh(bh);
	submit_bh(READ | REQ_META | REQ_PRIO, bh);
	wait_on_buffer(bh);
	if (!buffer_uptodate(bh)) {
		put_bh(bh);
		ext4_error(sb, "Cannot read inode bitmap - "
			   "block_group = %u, inode_bitmap = %llu",
			   block_group, bitmap_blk);
		return NULL;
	}

verify:
	ext4_lock_group(sb, block_group);
	if (!buffer_verified(bh) &&
	    !ext4_inode_bitmap_csum_verify(sb, block_group, desc, bh,
					   EXT4_INODES_PER_GROUP(sb) / 8)) {
		ext4_unlock_group(sb, block_group);
		put_bh(bh);
		ext4_error(sb, "Corrupt inode bitmap - block_group = %u, "
			   "inode_bitmap = %llu", block_group, bitmap_blk);
		return NULL;
	}
	ext4_unlock_group(sb, block_group);
	set_buffer_verified(bh);
	return bh;
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 *
 * HOWEVER: we must make sure that we get no aliases,
 * which means that we have to call "clear_inode()"
 * _before_ we mark the inode not in use in the inode
 * bitmaps. Otherwise a newly created file might use
 * the same inode number (not actually the same pointer
 * though), and then we'd have two inodes sharing the
 * same inode number and space on the harddisk.
 */
void ext4_free_inode(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	int is_directory;
	unsigned long ino;
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *bh2;
	ext4_group_t block_group;
	unsigned long bit;
	struct ext4_group_desc *gdp;
	struct ext4_super_block *es;
	struct ext4_sb_info *sbi;
	int fatal = 0, err, count, cleared;

	if (!sb) {
		printk(KERN_ERR "EXT4-fs: %s:%d: inode on "
		       "nonexistent device\n", __func__, __LINE__);
		return;
	}
	if (atomic_read(&inode->i_count) > 1) {
		ext4_msg(sb, KERN_ERR, "%s:%d: inode #%lu: count=%d",
			 __func__, __LINE__, inode->i_ino,
			 atomic_read(&inode->i_count));
		return;
	}
	if (inode->i_nlink) {
		ext4_msg(sb, KERN_ERR, "%s:%d: inode #%lu: nlink=%d\n",
			 __func__, __LINE__, inode->i_ino, inode->i_nlink);
		return;
	}
	sbi = EXT4_SB(sb);

	ino = inode->i_ino;
	ext4_debug("freeing inode %lu\n", ino);
	trace_ext4_free_inode(inode);

	/*
	 * Note: we must free any quota before locking the superblock,
	 * as writing the quota to disk may need the lock as well.
	 */
	dquot_initialize(inode);
	ext4_xattr_delete_inode(handle, inode);
	dquot_free_inode(inode);
	dquot_drop(inode);

	is_directory = S_ISDIR(inode->i_mode);

	/* Do this BEFORE marking the inode not in use or returning an error */
	ext4_clear_inode(inode);

	es = EXT4_SB(sb)->s_es;
	if (ino < EXT4_FIRST_INO(sb) || ino > le32_to_cpu(es->s_inodes_count)) {
		ext4_error(sb, "reserved or nonexistent inode %lu", ino);
		goto error_return;
	}
	block_group = (ino - 1) / EXT4_INODES_PER_GROUP(sb);
	bit = (ino - 1) % EXT4_INODES_PER_GROUP(sb);
	bitmap_bh = ext4_read_inode_bitmap(sb, block_group);
	if (!bitmap_bh)
		goto error_return;

	BUFFER_TRACE(bitmap_bh, "get_write_access");
	fatal = ext4_journal_get_write_access(handle, bitmap_bh);
	if (fatal)
		goto error_return;

	fatal = -ESRCH;
	gdp = ext4_get_group_desc(sb, block_group, &bh2);
	if (gdp) {
		BUFFER_TRACE(bh2, "get_write_access");
		fatal = ext4_journal_get_write_access(handle, bh2);
	}
	ext4_lock_group(sb, block_group);
	cleared = ext4_test_and_clear_bit(bit, bitmap_bh->b_data);
	if (fatal || !cleared) {
		ext4_unlock_group(sb, block_group);
		goto out;
	}

	count = ext4_free_inodes_count(sb, gdp) + 1;
	ext4_free_inodes_set(sb, gdp, count);
	if (is_directory) {
		count = ext4_used_dirs_count(sb, gdp) - 1;
		ext4_used_dirs_set(sb, gdp, count);
		percpu_counter_dec(&sbi->s_dirs_counter);
	}
	ext4_inode_bitmap_csum_set(sb, block_group, gdp, bitmap_bh,
				   EXT4_INODES_PER_GROUP(sb) / 8);
	ext4_group_desc_csum_set(sb, block_group, gdp);
	ext4_unlock_group(sb, block_group);

	percpu_counter_inc(&sbi->s_freeinodes_counter);
	if (sbi->s_log_groups_per_flex) {
		ext4_group_t f = ext4_flex_group(sbi, block_group);

		atomic_inc(&sbi->s_flex_groups[f].free_inodes);
		if (is_directory)
			atomic_dec(&sbi->s_flex_groups[f].used_dirs);
	}
	BUFFER_TRACE(bh2, "call ext4_handle_dirty_metadata");
	fatal = ext4_handle_dirty_metadata(handle, NULL, bh2);
out:
	if (cleared) {
		BUFFER_TRACE(bitmap_bh, "call ext4_handle_dirty_metadata");
		err = ext4_handle_dirty_metadata(handle, NULL, bitmap_bh);
		if (!fatal)
			fatal = err;
	} else
		ext4_error(sb, "bit already cleared for inode %lu", ino);

error_return:
	brelse(bitmap_bh);
	ext4_std_error(sb, fatal);
}

struct orlov_stats {
	__u64 free_clusters;
	__u32 free_inodes;
	__u32 used_dirs;
};

/*
 * Helper function for Orlov's allocator; returns critical information
 * for a particular block group or flex_bg.  If flex_size is 1, then g
 * is a block group number; otherwise it is flex_bg number.
 */
//得到块组或者flex group块组的空闲inode数、空闲block数、已使用的目录数
static void get_orlov_stats(struct super_block *sb, ext4_group_t g,
			    int flex_size, struct orlov_stats *stats)
{
	struct ext4_group_desc *desc;
	struct flex_groups *flex_group = EXT4_SB(sb)->s_flex_groups;

	if (flex_size > 1) {
        //flex group块组空闲inode数
		stats->free_inodes = atomic_read(&flex_group[g].free_inodes);
        //flex group块组空闲的cluster数，其实就是空闲block数，一个cluster一个block
		stats->free_clusters = atomic64_read(&flex_group[g].free_clusters);
        //flex group块组已使用的目录数
		stats->used_dirs = atomic_read(&flex_group[g].used_dirs);
		return;
	}

    //到这里说明没有使用 flex group块组，则得到g代表的块组的空闲inode数、空闲block数、已使用的目录树
	desc = ext4_get_group_desc(sb, g, NULL);
	if (desc) {
		stats->free_inodes = ext4_free_inodes_count(sb, desc);
		stats->free_clusters = ext4_free_group_clusters(sb, desc);
		stats->used_dirs = ext4_used_dirs_count(sb, desc);
	} else {
		stats->free_inodes = 0;
		stats->free_clusters = 0;
		stats->used_dirs = 0;
	}
}

/*
 * Orlov's allocator for directories.
 *
 * We always try to spread first-level directories.
 *
 * If there are blockgroups with both free inodes and free blocks counts
 * not worse than average we return one with smallest directory count.
 * Otherwise we simply return a random group.
 *
 * For the rest rules look so:
 *
 * It's OK to put directory into a group unless
 * it has too many directories already (max_dirs) or
 * it has too few free inodes left (min_inodes) or
 * it has too few free blocks left (min_blocks) or
 * Parent's group is preferred, if it doesn't satisfy these
 * conditions we search cyclically through the rest. If none
 * of the groups look good we just look for a group with more
 * free inodes than average (starting at parent's group).
 */
//找一个空闲inode数充裕、空闲block数充裕、已使用的目录很少的块组，把找到的块组号赋值给group
/*具体细节是
1:如果父目录是顶层目录或者根目录，则以best_ndir、avefreei、avefreec 为阈值，从0号块组或者
flex group块组向后一直查找，找到块组已使用目录数、块组空闲inode数、块组空闲block数符合阈值的
块组。找到后，如果不是flex group块组，直接返回这个块组号。如果是flex group块组，
则从该flex group块组找一个空闲inode充足的块组。

2:如果父目录不是顶层目录或者根目录，则以max_dirs、min_inodes、min_clusters为阈值，
从0号块组或者flex group块组向后一直查找，找到块组已使用目录数、块组空闲inode数、块组空闲
block数符合阈值的块组。找到后，如果不是flex group块组，如果是flex group块组，
则从该flex group块组找一个空闲inode充足的块组

3:如果按照步骤1和2找不到合适的块组，则从0号块组或者flex group块组向后一直查找，只要块组
空闲inode数充裕，直接返回该块组号

总结: parent_group 是个关键，它是搜索空闲块组(有空闲inode和block)的基准块组号
1:是顶层目录或者根目录时，则采用分散形式查找空闲块组，因为此时parent_group = (unsigned)grp % ngroups，parent_group是个随机值
2:如果不是顶层目录或根目录，才在父目录所属块组附近查找空闲块组，因为此时parent_group = EXT4_I(parent)->i_block_group，就是父目录所属的块组编号
3:如果最后找不到合适的空闲块组，那就没那么多限制条件了，从0号块组开始遍历，谁有空闲inode就选中谁作为最终的块组
*/
static int find_group_orlov(struct super_block *sb, struct inode *parent,
			    ext4_group_t *group, umode_t mode,
			    const struct qstr *qstr)//qstr是创建的目录名字
{
    //父inode所属的块组编号
	ext4_group_t parent_group = EXT4_I(parent)->i_block_group;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
    //块组个数
	ext4_group_t real_ngroups = ext4_get_groups_count(sb);
    //每个块组的最多的inode数
	int inodes_per_group = EXT4_INODES_PER_GROUP(sb);
	unsigned int freei, avefreei, grp_free;
	ext4_fsblk_t freeb, avefreec;
	unsigned int ndirs;
	int max_dirs, min_inodes;
	ext4_grpblk_t min_clusters;
	ext4_group_t i, grp, g, ngroups;
	struct ext4_group_desc *desc;
	struct orlov_stats stats;
    //flex group包含的块组个数，16
	int flex_size = ext4_flex_bg_size(sbi);
	struct dx_hash_info hinfo;

	ngroups = real_ngroups;
	if (flex_size > 1) {
		ngroups = (real_ngroups + flex_size - 1) >>
			sbi->s_log_groups_per_flex;
		parent_group >>= sbi->s_log_groups_per_flex;
	}
    //空闲inode数
	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
    //平均每个块组的空闲inode数
	avefreei = freei / ngroups;
    //空闲block数
	freeb = EXT4_C2B(sbi,
		percpu_counter_read_positive(&sbi->s_freeclusters_counter));
	avefreec = freeb;
    //avefreec = avefreec/ngroups 平均每个块组空闲block数
	do_div(avefreec, ngroups);
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);

    /*这个if成立应该说明父目录是根目录或者顶层目录*/
	if (S_ISDIR(mode) &&
	    ((parent == sb->s_root->d_inode) ||//父目录是根文件系统根目录
	     (ext4_test_inode_flag(parent, EXT4_INODE_TOPDIR))))//顶层目录
    {
	    //每个块组最多的inode数
		int best_ndir = inodes_per_group;
		int ret = -1;

        //下边这是根据各种规则计算一个初始块组号赋于grp
		if (qstr) {
			hinfo.hash_version = DX_HASH_HALF_MD4;
			hinfo.seed = sbi->s_hash_seed;
			ext4fs_dirhash(qstr->name, qstr->len, &hinfo);
			grp = hinfo.hash;
		} else
			get_random_bytes(&grp, sizeof(grp));
        //parent_group就是上边的初始块组号grp
		parent_group = (unsigned)grp % ngroups;

        //从0号块组依次向后查找，看哪个块组有充裕的inode和block
        /*有个疑问，如果使用flex group块组的情况下，ngroups应该是flex group组个数，
        一个flex group组有16个真正的块组*/
		for (i = 0; i < ngroups; i++) {
			g = (parent_group + i) % ngroups;
            //得到块组或者flex group块组的空闲inode数、空闲block数、已使用的目录数
			get_orlov_stats(sb, g, flex_size, &stats);
            //当前块组(或者flex group块组)，没有空闲inode，跳过
			if (!stats.free_inodes)
				continue;
            //这个成立说明当前块组(或者flex group块组)已使用的目录太多，高于每个块组最大inode数，跳过
			if (stats.used_dirs >= best_ndir)
				continue;
            //这个成立说明当前块组(或者flex group块组)空闲inode太少，低于平均值，跳过
			if (stats.free_inodes < avefreei)
				continue;
            //这个成立说明当前块组(或者flex group块组)空闲block太少，低于平均值，跳过
			if (stats.free_clusters < avefreec)
				continue;
            
            /*到这里很奇怪，明明已经找到inode、block等充足的块组g，但却没有跳转for循环，而是
            继续for循环查找下一个inode充足的块组，直到遍历到最后一个块组，搞不清楚*/
			grp = g;
			ret = 0;
            //这里更新best_ndir!!!!!!!!!
			best_ndir = stats.used_dirs;
		}

        //如果上边for循环找到inode充足等的块组，则ret是0。否则没有找到inode、block充足等的块组，
        //ret是-1，直接跳转到fallback分支
		if (ret)
			goto fallback;
        
	found_flex_bg:
        
        //没有使用flex group块组则直接使用grp作为本次找到的块组号
		if (flex_size == 1) {
			*group = grp;
			return 0;
		}

		/*
		 * We pack inodes at the beginning of the flexgroup's
		 * inode tables.  Block allocation decisions will do
		 * something similar, although regular files will
		 * start at 2nd block group of the flexgroup.  See
		 * ext4_ext_find_goal() and ext4_find_near().
		 */
		//到这里说明grp是flex group块组的编号
        //令grp乘以flex_size(16)，之后grp应该就是真正的块组号，一个flex group组有16个块组
        grp *= flex_size;

        //这里应该是在选中的flex group组里的16个块组里，找一个空闲inode充足的块组，
        //然后执行*group = grp+i就return，这就是最终选中的块组
		for (i = 0; i < flex_size; i++) {
			if (grp+i >= real_ngroups)//real_ngroups是最大块组树
				break;
			desc = ext4_get_group_desc(sb, grp+i, NULL);
			if (desc && ext4_free_inodes_count(sb, desc)) {
				*group = grp+i;
				return 0;
			}
		}
		goto fallback;
	}

    /*到这里，一般情况是，父目录不是顶层目录或者根目录*/
    
    //计算块组最大目录个数上限max_dirs
	max_dirs = ndirs / ngroups + inodes_per_group / 16;
    //减少avefreei，块组空闲inode数下限
	min_inodes = avefreei - inodes_per_group*flex_size / 4;
	if (min_inodes < 1)
		min_inodes = 1;
    //减少avefreec，块组空闲block数下限
	min_clusters = avefreec - EXT4_CLUSTERS_PER_GROUP(sb)*flex_size / 4;

	/*
	 * Start looking in the flex group where we last allocated an
	 * inode for this parent directory
	 */
	if (EXT4_I(parent)->i_last_alloc_group != ~0) {
        //取出父目录上一次分配inode所属的块组号给parent_group，作为本次查找块组的基准值
		parent_group = EXT4_I(parent)->i_last_alloc_group;
		if (flex_size > 1)
			parent_group >>= sbi->s_log_groups_per_flex;
	}
    //从0号块组向后遍历，找到一个inode充足的块组
	for (i = 0; i < ngroups; i++) {
        //其实就是父目录所在group加i
		grp = (parent_group + i) % ngroups;
        //得到块组或者flex group块组的空闲inode数、空闲block数、已使用的目录数
		get_orlov_stats(sb, grp, flex_size, &stats);
        //这个成立说明当前块组(或者flex group块组)已使用的目录太多，高于每个块组最大inode数，跳过
		if (stats.used_dirs >= max_dirs)
			continue;
        //这个成立说明当前块组(或者flex group块组)空闲inode太少，低于平均值，跳过
		if (stats.free_inodes < min_inodes)
			continue;
        //这个成立说明当前块组(或者flex group块组)空闲block太少，低于平均值，跳过
		if (stats.free_clusters < min_clusters)
			continue;

        //到这里说明找到一个空闲inode充裕的块组(或者flex group块组)，块组号是grp。
        //则跳到found_flex_bg分支，如果是flex group组则从该flex group找一个空闲inode充裕的块组
		goto found_flex_bg;
	}

fallback:
	ngroups = real_ngroups;
    //平均每个块组空闲inode数
	avefreei = freei / ngroups;

    /*到这里，说明上边按照 "块组或者flex group块组的空闲inode数、空闲block数、已使用的
    目录数" 的规则，找不到合适的块组。于是下边放松条件，重新找一个空闲inode充裕的块组*/
    
fallback_retry:
    //父目录所属块组号
	parent_group = EXT4_I(parent)->i_block_group;
    //从0号块组或者flex group块组向后遍历，找到一个inode充足的块组或者flex group块组
	for (i = 0; i < ngroups; i++) {
        //其实就是父目录所在块组号或者flex group块组号加i得到快组号grp
		grp = (parent_group + i) % ngroups;
		desc = ext4_get_group_desc(sb, grp, NULL);
		if (desc) {
            //如果grp这个块组或者flex group块组空闲inode数大于avefreei(平均每个块组空闲inode数)，那它就是本次选中的块组
			grp_free = ext4_free_inodes_count(sb, desc);
			if (grp_free && grp_free >= avefreei) {
				*group = grp;
				return 0;
			}
		}
	}

	if (avefreei) {
		/*
		 * The free-inodes counter is approximate, and for really small
		 * filesystems the above test can fail to find any blockgroups
		 */
		avefreei = 0;
		goto fallback_retry;
	}

	return -1;
}
//使用flex group时，先在父目录所属flex group的16个块组里找一个有空闲inode的块组，找不到就
//执行find_group_orlov()找一个有充裕空闲inode和block的flex group块组。不使用flex group时，先看父目录所属块组有没有
//空闲的inode和block，有就返回父目录的块组号。没有就遍历一个个块组，看哪个块组有空闲的inode。
static int find_group_other(struct super_block *sb, struct inode *parent,
			    ext4_group_t *group, umode_t mode)
{
    //父目录所在块组
	ext4_group_t parent_group = EXT4_I(parent)->i_block_group;
	ext4_group_t i, last, ngroups = ext4_get_groups_count(sb);
	struct ext4_group_desc *desc;
	int flex_size = ext4_flex_bg_size(EXT4_SB(sb));

	/*
	 * Try to place the inode is the same flex group as its
	 * parent.  If we can't find space, use the Orlov algorithm to
	 * find another flex group, and store that information in the
	 * parent directory's inode information so that use that flex
	 * group for future allocations.
	 */
	if (flex_size > 1)//使用了flex group块组
    {
		int retry = 0;

	try_again:
        //parent_group是父目录，这里计算的parent_group是父目录所属flex group块组里的第一个块组号
		parent_group &= ~(flex_size-1);
        //last是parent_group所属flex group块组里最后一个块组号
		last = parent_group + flex_size;
		if (last > ngroups)
			last = ngroups;
        //从flex group块组里第1个块组搜索到最后1个块组
		for  (i = parent_group; i < last; i++) {
            //取出该块组的描述符
			desc = ext4_get_group_desc(sb, i, NULL);
            //该块组有空闲的inode，那它就是选中的块组
			if (desc && ext4_free_inodes_count(sb, desc)) {
				*group = i;
				return 0;
			}
		}
        //这里是取出父目录分配inode所属块组号i_last_alloc_group，再尝试一次
		if (!retry && EXT4_I(parent)->i_last_alloc_group != ~0) {
			retry = 1;
			parent_group = EXT4_I(parent)->i_last_alloc_group;
			goto try_again;
		}
		/*
		 * If this didn't work, use the Orlov search algorithm
		 * to find a new flex group; we pass in the mode to
		 * avoid the topdir algorithms.
		 */
		 
		/*到这里说明在父目录所属flex group中的所16个块组，都没有空闲inode，于是下边执行
        find_group_orlov()再找一个合适的flex group块组*/
		*group = parent_group + flex_size;
		if (*group > ngroups)
			*group = 0;
        
        //找一个空闲inode数充裕、空闲block数充裕、已使用的目录很少的flex group块组，把找到的flex group块组号赋值给group
		return find_group_orlov(sb, parent, group, mode, NULL);
	}

    /*执行到这里，说明没有使用flex group*/
    
	/*
	 * Try to place the inode in its parent directory
	 */
	//如果父目录所属块组有空闲inode和block，那这个块组就是本次选中的块组
	*group = parent_group;
	desc = ext4_get_group_desc(sb, *group, NULL);
	if (desc && ext4_free_inodes_count(sb, desc) &&
	    ext4_free_group_clusters(sb, desc))
		return 0;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */

    /*执行到这里，说明没有使用flex group，并且父目录所属块组没有空闲的inode和block*/

    //这里计算后group应该是父目录所在块组的下一个块组号
	*group = (*group + parent->i_ino) % ngroups;

	/*
	 * Use a quadratic hash to find a group with a free inode and some free
	 * blocks.
	 */
	//从group对应的块组一直向后搜索
	for (i = 1; i < ngroups; i <<= 1) {//搞不清楚i <<= 1 是什么意思???????
	    //group块组号每次增加1、2、4、8、16.......
		*group += i;
		if (*group >= ngroups)
			*group -= ngroups;

		desc = ext4_get_group_desc(sb, *group, NULL);
        //新找到的块组group有空闲的inode和block，那它就是要找到的块组
		if (desc && ext4_free_inodes_count(sb, desc) &&
		    ext4_free_group_clusters(sb, desc))
			return 0;
	}

	/*
	 * That failed: try linear search for a free inode, even if that group
	 * has no free blocks.
	 */

    /*执行到这里，还没找到合适的块组，于是下边放宽查找块组的限制条件*/
	*group = parent_group;

	for (i = 0; i < ngroups; i++) {
        //group块组号每次只增加1
		if (++*group >= ngroups)
			*group = 0;
		desc = ext4_get_group_desc(sb, *group, NULL);
        //新找到的块组group有空闲的inode，那它就是要找到的块组，这里不再看是否有空闲block限制
		if (desc && ext4_free_inodes_count(sb, desc))
			return 0;
	}

	return -1;
}

/*
 * There are two policies for allocating an inode.  If the new inode is
 * a directory, then a forward search is made for a block group with both
 * free space and a low directory-to-inode ratio; if that fails, then of
 * the groups with above-average free space, that group with the fewest
 * directories already is chosen.
 *
 * For other inodes, search forward from the parent directory's block
 * group to find a free inode.
 */
//找到一个合适的块组，从这个块组分配一个空闲inode
struct inode *__ext4_new_inode(handle_t *handle, struct inode *dir,
			       umode_t mode, const struct qstr *qstr,//qstr是待创建的目录或文件名字
			       __u32 goal, uid_t *owner, int handle_type,//创建目录和文件时goal都是0
			       unsigned int line_no, int nblocks)
{
	struct super_block *sb;
	struct buffer_head *inode_bitmap_bh = NULL;
	struct buffer_head *group_desc_bh;
	ext4_group_t ngroups, group = 0;
	unsigned long ino = 0;
	struct inode *inode;
	struct ext4_group_desc *gdp = NULL;
	struct ext4_inode_info *ei;
	struct ext4_sb_info *sbi;
	int ret2, err = 0;
	struct inode *ret;
	ext4_group_t i;
	ext4_group_t flex_group;

	/* Cannot create files in a deleted directory */
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);

	sb = dir->i_sb;
    //总块组个数
	ngroups = ext4_get_groups_count(sb);
	trace_ext4_request_inode(dir, mode);
    //分配ext4_inode_info结构并返回它的成员struct inode vfs_inode的地址
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
    //由inode得到ext4_inode_info
	ei = EXT4_I(inode);
    //由sb得到ext4_sb_info
	sbi = EXT4_SB(sb);

	/*
	 * Initalize owners and quota early so that we don't have to account
	 * for quota initialization worst case in standard inode creating
	 * transaction
	 */
	if (owner) {
		inode->i_mode = mode;
		i_uid_write(inode, owner[0]);
		i_gid_write(inode, owner[1]);
	} else if (test_opt(sb, GRPID)) {
		inode->i_mode = mode;
		inode->i_uid = current_fsuid();
		inode->i_gid = dir->i_gid;
	} else
		inode_init_owner(inode, dir, mode);
	dquot_initialize(inode);

	if (!goal)//创建目录和文件时goal都是0
		goal = sbi->s_inode_goal;//sbi->s_inode_goal是0

	if (goal && goal <= le32_to_cpu(sbi->s_es->s_inodes_count)) {//if不成立
		group = (goal - 1) / EXT4_INODES_PER_GROUP(sb);
		ino = (goal - 1) % EXT4_INODES_PER_GROUP(sb);
		ret2 = 0;
		goto got_group;
	}

    /*下边为新创建的文件或目录先找到一个有空闲inode和空闲block的块组，优先查找父目录所属块组。查找失败则遍历所有块组，
       看哪个有空闲inode和block。找到合适块组把块组号赋值给group，接着会在该块组分配一个空闲的inode编号*/
	if (S_ISDIR(mode))//创建的是文件inode
		ret2 = find_group_orlov(sb, dir, &group, mode, qstr);
	else//创建的是文件inode
		ret2 = find_group_other(sb, dir, &group, mode);

got_group:
    //记录最近一次分配的inode所属的块组。到这里group就是本次要分配的inode所属的块组编号
	EXT4_I(dir)->i_last_alloc_group = group;
	err = -ENOSPC;
	if (ret2 == -1)
		goto out;

	/*
	 * Normally we will only go through one pass of this loop,
	 * unless we get unlucky and it turns out the group we selected
	 * had its last inode grabbed by someone else.
	 */
	for (i = 0; i < ngroups; i++, ino = 0) {//ngroups是ext4文件系统总的块组数
		err = -EIO;
        //由块组编号group得到块组描述符结构ext4_group_desc，并且令group_desc_bh指向保存
        //块组描述符数据的物理块映射的bh
		gdp = ext4_get_group_desc(sb, group, &group_desc_bh);
		if (!gdp)
			goto out;

		/*
		 * Check free inodes count before loading bitmap.
		 */
		//块组要是空闲inode不够了，group加1指向下一个块组，如果group是最后一个块组则从
		//第一个块组开始
		if (ext4_free_inodes_count(sb, gdp) == 0) {
			if (++group == ngroups)
				group = 0;
			continue;
		}

		brelse(inode_bitmap_bh);
        //先根据块组号group得到块组描述符ext4_group_desc，再由块组描述符得到保存
        //inode bitmap数据的物理块号，最后读取该inode bitmap物理块的4K数据到inode_bitmap_bh
        //并返回。注意，每个块组的inode bitmap应该只占一个物理块，最大数据量是4K
		inode_bitmap_bh = ext4_read_inode_bitmap(sb, group);
		if (!inode_bitmap_bh)
			goto out;

repeat_in_this_group:
        /*一个块组内，inode bitmap占一个物理块，4K大小，总计有4k*8个bit。因此，理论上
        一个块组内最多可以容纳4k*8个inode，但实际上只有EXT4_INODES_PER_GROUP(sb)个，即
        8192个，这个应该是综合考虑的结果，一个块组实际容纳不了4k*8个inode。*/
        //在inode bitmap对应的inode_bitmap_bh->b_data[]这4K数据中，找一个空闲的inode号。
        //每在inode bitmap找一个空闲inode号，在对应的inode bitmap的bit位置1。比如
        //inode bitmap的buf即inode_bitmap_bh->b_data[]的第1个字节的第1个bit是0，则
        //给本次的inode分配的inode编号就是0，然后下边把这个bit位置1。下次分配新的inode，
        //找到inode_bitmap_bh->b_data[]的第1个字节的第2个bit，则为该新inode分配的编号是1.
        //inode_bitmap_bh->b_data[]某个bit位是1表示对应编号inode分配了，为0表示该bit位对应的inode空闲
		ino = ext4_find_next_zero_bit((unsigned long *)
					      inode_bitmap_bh->b_data,
					      EXT4_INODES_PER_GROUP(sb), ino);
        //新分配的inode编号大于最大值，则说明当前块组inode用完了，则去下一个块组分配inode
		if (ino >= EXT4_INODES_PER_GROUP(sb))
			goto next_group;
		if (group == 0 && (ino+1) < EXT4_FIRST_INO(sb)) {
			ext4_error(sb, "reserved inode found cleared - "
				   "inode=%lu", ino + 1);
			continue;
		}
		if (!handle) {
			BUG_ON(nblocks <= 0);
			handle = __ext4_journal_start_sb(dir->i_sb, line_no,
							 handle_type, nblocks);
			if (IS_ERR(handle)) {
				err = PTR_ERR(handle);
				ext4_std_error(sb, err);
				goto out;
			}
		}
		BUFFER_TRACE(inode_bitmap_bh, "get_write_access");
		err = ext4_journal_get_write_access(handle, inode_bitmap_bh);
		if (err) {
			ext4_std_error(sb, err);
			goto out;
		}
		ext4_lock_group(sb, group);
        //把inode bitmap的buf即inode_bitmap_bh->b_data[]数组的ino对应的bit位置1，表示该
        //bit位对应的inode已经分配了，下次再分配inode就跳过该bit位，找一个新的是0的bit位。
		ret2 = ext4_test_and_set_bit(ino, inode_bitmap_bh->b_data);
		ext4_unlock_group(sb, group);
        //搞不清楚为什么这里要加1?我猜测应该是以1为最小inode编号，以1为base
		ino++;		/* the inode bitmap is zero-based */
		if (!ret2)//在group块组成功分配一个inode编号是ino的inode(空闲的inode)，跳出循环
			goto got; /* we grabbed the inode! */

        //执行到这里，说明没有找一个空闲的inode编号，则跳到repeat_in_this_group分支重新在
        //inode bitmap的buf即inode_bitmap_bh->b_data[]数组重新找一个空闲的inode编号
		if (ino < EXT4_INODES_PER_GROUP(sb))
			goto repeat_in_this_group;
next_group:
        //到这里说明已经遍历到最后一个块组，还是没找到有空闲inode的块组，那就从第一个块组中找一个空闲的inode
		if (++group == ngroups)
			group = 0;
	}
	err = -ENOSPC;
	goto out;

got:
	BUFFER_TRACE(inode_bitmap_bh, "call ext4_handle_dirty_metadata");
    //inode bitmap的buf即inode_bitmap_bh->b_data[]数组的数据脏了，因为上边分配一个空闲的
    //inode，把该buf里inode编号对应的bit位置1
	err = ext4_handle_dirty_metadata(handle, NULL, inode_bitmap_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	err = ext4_journal_get_write_access(handle, group_desc_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	/* We may have to initialize the block bitmap if it isn't already */
	if (ext4_has_group_desc_csum(sb) &&
	    gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
		struct buffer_head *block_bitmap_bh;

		block_bitmap_bh = ext4_read_block_bitmap(sb, group);
		if (!block_bitmap_bh) {
			err = -EIO;
			goto out;
		}
		BUFFER_TRACE(block_bitmap_bh, "get block bitmap access");
		err = ext4_journal_get_write_access(handle, block_bitmap_bh);
		if (err) {
			brelse(block_bitmap_bh);
			ext4_std_error(sb, err);
			goto out;
		}

		BUFFER_TRACE(block_bitmap_bh, "dirty block bitmap");
		err = ext4_handle_dirty_metadata(handle, NULL, block_bitmap_bh);

		/* recheck and clear flag under lock if we still need to */
		ext4_lock_group(sb, group);
		if (gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~EXT4_BG_BLOCK_UNINIT);
			ext4_free_group_clusters_set(sb, gdp,
				ext4_free_clusters_after_init(sb, group, gdp));
			ext4_block_bitmap_csum_set(sb, group, gdp,
						   block_bitmap_bh);
			ext4_group_desc_csum_set(sb, group, gdp);
		}
		ext4_unlock_group(sb, group);
		brelse(block_bitmap_bh);

		if (err) {
			ext4_std_error(sb, err);
			goto out;
		}
	}

	/* Update the relevant bg descriptor fields */
	if (ext4_has_group_desc_csum(sb)) {
		int free;
		struct ext4_group_info *grp = ext4_get_group_info(sb, group);

		down_read(&grp->alloc_sem); /* protect vs itable lazyinit */
		ext4_lock_group(sb, group); /* while we modify the bg desc */
		free = EXT4_INODES_PER_GROUP(sb) -
			ext4_itable_unused_count(sb, gdp);
		if (gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~EXT4_BG_INODE_UNINIT);
			free = 0;
		}
		/*
		 * Check the relative inode number against the last used
		 * relative inode number in this group. if it is greater
		 * we need to update the bg_itable_unused count
		 */
		if (ino > free)
			ext4_itable_unused_set(sb, gdp,
					(EXT4_INODES_PER_GROUP(sb) - ino));
		up_read(&grp->alloc_sem);
	} else {
		ext4_lock_group(sb, group);
	}
    //令gdp对应的块组空闲的inode数减1
	ext4_free_inodes_set(sb, gdp, ext4_free_inodes_count(sb, gdp) - 1);
	if (S_ISDIR(mode)) {
        //设置块组的已分配的目录inode个数加1
		ext4_used_dirs_set(sb, gdp, ext4_used_dirs_count(sb, gdp) + 1);
		if (sbi->s_log_groups_per_flex) {
			ext4_group_t f = ext4_flex_group(sbi, group);

			atomic_inc(&sbi->s_flex_groups[f].used_dirs);
		}
	}
	if (ext4_has_group_desc_csum(sb)) {
		ext4_inode_bitmap_csum_set(sb, group, gdp, inode_bitmap_bh,
					   EXT4_INODES_PER_GROUP(sb) / 8);
		ext4_group_desc_csum_set(sb, group, gdp);
	}
	ext4_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh, "call ext4_handle_dirty_metadata");
    //前边修改了块组描述符的数据，比如块组空闲inode数，现在使块组描述符的buffer_head标记脏
	err = ext4_handle_dirty_metadata(handle, NULL, group_desc_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}
    //空闲inode数减1
	percpu_counter_dec(&sbi->s_freeinodes_counter);
	if (S_ISDIR(mode))
		percpu_counter_inc(&sbi->s_dirs_counter);//当前要创建的是目录时减1

	if (sbi->s_log_groups_per_flex) {// 4
		flex_group = ext4_flex_group(sbi, group);
		atomic_dec(&sbi->s_flex_groups[flex_group].free_inodes);
	}
    //根据为inode分配的块组编号group和在块组内找到的一个空闲inode号，计算最终的inode编号
	inode->i_ino = ino + group * EXT4_INODES_PER_GROUP(sb);
	/* This is the optimal IO size (for stat), not the fs block size */
	inode->i_blocks = 0;
    //计算当前inode的创建和修改时间
	inode->i_mtime = inode->i_atime = inode->i_ctime = ei->i_crtime =
						       ext4_current_time(inode);
    //对struct ext4_inode_info *ei赋值
	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_dir_start_lookup = 0;
	ei->i_disksize = 0;

	/* Don't inherit extent flag from directory, amongst others. */
	ei->i_flags =
		ext4_mask_flags(mode, EXT4_I(dir)->i_flags & EXT4_FL_INHERITED);
	ei->i_file_acl = 0;
	ei->i_dtime = 0;
	ei->i_block_group = group;
	ei->i_last_alloc_group = ~0;

	ext4_set_inode_flags(inode);
	if (IS_DIRSYNC(inode))
		ext4_handle_sync(handle);
	if (insert_inode_locked(inode) < 0) {
		/*
		 * Likely a bitmap corruption causing inode to be allocated
		 * twice.
		 */
		err = -EIO;
		ext4_error(sb, "failed to insert inode %lu: doubly allocated?",
			   inode->i_ino);
		goto out;
	}
	spin_lock(&sbi->s_next_gen_lock);
	inode->i_generation = sbi->s_next_generation++;
	spin_unlock(&sbi->s_next_gen_lock);

	/* Precompute checksum seed for inode metadata */
	if (EXT4_HAS_RO_COMPAT_FEATURE(sb,
			EXT4_FEATURE_RO_COMPAT_METADATA_CSUM)) {
		__u32 csum;
		__le32 inum = cpu_to_le32(inode->i_ino);
		__le32 gen = cpu_to_le32(inode->i_generation);
		csum = ext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum,
				   sizeof(inum));
		ei->i_csum_seed = ext4_chksum(sbi, csum, (__u8 *)&gen,
					      sizeof(gen));
	}

	ext4_clear_state_flags(ei); /* Only relevant on 32-bit archs */
	ext4_set_inode_state(inode, EXT4_STATE_NEW);

	ei->i_extra_isize = EXT4_SB(sb)->s_want_extra_isize;

	ei->i_inline_off = 0;
	if (EXT4_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_INLINE_DATA))
		ext4_set_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);

	ret = inode;
	err = dquot_alloc_inode(inode);
	if (err)
		goto fail_drop;

	err = ext4_init_acl(handle, inode, dir);
	if (err)
		goto fail_free_drop;

	err = ext4_init_security(handle, inode, dir, qstr);
	if (err)
		goto fail_free_drop;

	if (EXT4_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_EXTENTS)) {
		/* set extent flag only for directory, file and normal symlink*/
		if (S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode)) {
			ext4_set_inode_flag(inode, EXT4_INODE_EXTENTS);
			ext4_ext_tree_init(handle, inode);
		}
	}

	if (ext4_handle_valid(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		ei->i_datasync_tid = handle->h_transaction->t_tid;
	}

	err = ext4_mark_inode_dirty(handle, inode);
	if (err) {
		ext4_std_error(sb, err);
		goto fail_free_drop;
	}

	ext4_debug("allocating inode %lu\n", inode->i_ino);
	trace_ext4_allocate_inode(inode, dir, mode);
	brelse(inode_bitmap_bh);
	return ret;

fail_free_drop:
	dquot_free_inode(inode);
fail_drop:
	clear_nlink(inode);
	unlock_new_inode(inode);
out:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	iput(inode);
	brelse(inode_bitmap_bh);
	return ERR_PTR(err);
}

/* Verify that we are loading a valid orphan from disk */
struct inode *ext4_orphan_get(struct super_block *sb, unsigned long ino)
{
	unsigned long max_ino = le32_to_cpu(EXT4_SB(sb)->s_es->s_inodes_count);
	ext4_group_t block_group;
	int bit;
	struct buffer_head *bitmap_bh;
	struct inode *inode = NULL;
	long err = -EIO;

	/* Error cases - e2fsck has already cleaned up for us */
	if (ino > max_ino) {
		ext4_warning(sb, "bad orphan ino %lu!  e2fsck was run?", ino);
		goto error;
	}

	block_group = (ino - 1) / EXT4_INODES_PER_GROUP(sb);
	bit = (ino - 1) % EXT4_INODES_PER_GROUP(sb);
	bitmap_bh = ext4_read_inode_bitmap(sb, block_group);
	if (!bitmap_bh) {
		ext4_warning(sb, "inode bitmap error for orphan %lu", ino);
		goto error;
	}

	/* Having the inode bit set should be a 100% indicator that this
	 * is a valid orphan (no e2fsck run on fs).  Orphans also include
	 * inodes that were being truncated, so we can't check i_nlink==0.
	 */
	if (!ext4_test_bit(bit, bitmap_bh->b_data))
		goto bad_orphan;

	inode = ext4_iget(sb, ino);
	if (IS_ERR(inode))
		goto iget_failed;

	/*
	 * If the orphans has i_nlinks > 0 then it should be able to be
	 * truncated, otherwise it won't be removed from the orphan list
	 * during processing and an infinite loop will result.
	 */
	if (inode->i_nlink && !ext4_can_truncate(inode))
		goto bad_orphan;

	if (NEXT_ORPHAN(inode) > max_ino)
		goto bad_orphan;
	brelse(bitmap_bh);
	return inode;

iget_failed:
	err = PTR_ERR(inode);
	inode = NULL;
bad_orphan:
	ext4_warning(sb, "bad orphan inode %lu!  e2fsck was run?", ino);
	printk(KERN_WARNING "ext4_test_bit(bit=%d, block=%llu) = %d\n",
	       bit, (unsigned long long)bitmap_bh->b_blocknr,
	       ext4_test_bit(bit, bitmap_bh->b_data));
	printk(KERN_WARNING "inode=%p\n", inode);
	if (inode) {
		printk(KERN_WARNING "is_bad_inode(inode)=%d\n",
		       is_bad_inode(inode));
		printk(KERN_WARNING "NEXT_ORPHAN(inode)=%u\n",
		       NEXT_ORPHAN(inode));
		printk(KERN_WARNING "max_ino=%lu\n", max_ino);
		printk(KERN_WARNING "i_nlink=%u\n", inode->i_nlink);
		/* Avoid freeing blocks if we got a bad deleted inode */
		if (inode->i_nlink == 0)
			inode->i_blocks = 0;
		iput(inode);
	}
	brelse(bitmap_bh);
error:
	return ERR_PTR(err);
}

unsigned long ext4_count_free_inodes(struct super_block *sb)
{
	unsigned long desc_count;
	struct ext4_group_desc *gdp;
	ext4_group_t i, ngroups = ext4_get_groups_count(sb);
#ifdef EXT4FS_DEBUG
	struct ext4_super_block *es;
	unsigned long bitmap_count, x;
	struct buffer_head *bitmap_bh = NULL;

	es = EXT4_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;
	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += ext4_free_inodes_count(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = ext4_read_inode_bitmap(sb, i);
		if (!bitmap_bh)
			continue;

		x = ext4_count_free(bitmap_bh->b_data,
				    EXT4_INODES_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %lu: stored = %d, counted = %lu\n",
			(unsigned long) i, ext4_free_inodes_count(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "ext4_count_free_inodes: "
	       "stored = %u, computed = %lu, %lu\n",
	       le32_to_cpu(es->s_free_inodes_count), desc_count, bitmap_count);
	return desc_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += ext4_free_inodes_count(sb, gdp);
		cond_resched();
	}
	return desc_count;
#endif
}

/* Called at mount-time, super-block is locked */
unsigned long ext4_count_dirs(struct super_block * sb)
{
	unsigned long count = 0;
	ext4_group_t i, ngroups = ext4_get_groups_count(sb);

	for (i = 0; i < ngroups; i++) {
		struct ext4_group_desc *gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		count += ext4_used_dirs_count(sb, gdp);
	}
	return count;
}

/*
 * Zeroes not yet zeroed inode table - just write zeroes through the whole
 * inode table. Must be called without any spinlock held. The only place
 * where it is called from on active part of filesystem is ext4lazyinit
 * thread, so we do not need any special locks, however we have to prevent
 * inode allocation from the current group, so we take alloc_sem lock, to
 * block ext4_new_inode() until we are finished.
 */
int ext4_init_inode_table(struct super_block *sb, ext4_group_t group,
				 int barrier)
{
	struct ext4_group_info *grp = ext4_get_group_info(sb, group);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_group_desc *gdp = NULL;
	struct buffer_head *group_desc_bh;
	handle_t *handle;
	ext4_fsblk_t blk;
	int num, ret = 0, used_blks = 0;

	/* This should not happen, but just to be sure check this */
	if (sb->s_flags & MS_RDONLY) {
		ret = 1;
		goto out;
	}

	gdp = ext4_get_group_desc(sb, group, &group_desc_bh);
	if (!gdp)
		goto out;

	/*
	 * We do not need to lock this, because we are the only one
	 * handling this flag.
	 */
	if (gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_ZEROED))
		goto out;

	handle = ext4_journal_start_sb(sb, EXT4_HT_MISC, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out;
	}

	down_write(&grp->alloc_sem);
	/*
	 * If inode bitmap was already initialized there may be some
	 * used inodes so we need to skip blocks with used inodes in
	 * inode table.
	 */
	if (!(gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)))
		used_blks = DIV_ROUND_UP((EXT4_INODES_PER_GROUP(sb) -
			    ext4_itable_unused_count(sb, gdp)),
			    sbi->s_inodes_per_block);

	if ((used_blks < 0) || (used_blks > sbi->s_itb_per_group)) {
		ext4_error(sb, "Something is wrong with group %u: "
			   "used itable blocks: %d; "
			   "itable unused count: %u",
			   group, used_blks,
			   ext4_itable_unused_count(sb, gdp));
		ret = 1;
		goto err_out;
	}

	blk = ext4_inode_table(sb, gdp) + used_blks;
	num = sbi->s_itb_per_group - used_blks;

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	ret = ext4_journal_get_write_access(handle,
					    group_desc_bh);
	if (ret)
		goto err_out;

	/*
	 * Skip zeroout if the inode table is full. But we set the ZEROED
	 * flag anyway, because obviously, when it is full it does not need
	 * further zeroing.
	 */
	if (unlikely(num == 0))
		goto skip_zeroout;

	ext4_debug("going to zero out inode table in group %d\n",
		   group);
	ret = sb_issue_zeroout(sb, blk, num, GFP_NOFS);
	if (ret < 0)
		goto err_out;
	if (barrier)
		blkdev_issue_flush(sb->s_bdev, GFP_NOFS, NULL);

skip_zeroout:
	ext4_lock_group(sb, group);
	gdp->bg_flags |= cpu_to_le16(EXT4_BG_INODE_ZEROED);
	ext4_group_desc_csum_set(sb, group, gdp);
	ext4_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh,
		     "call ext4_handle_dirty_metadata");
	ret = ext4_handle_dirty_metadata(handle, NULL,
					 group_desc_bh);

err_out:
	up_write(&grp->alloc_sem);
	ext4_journal_stop(handle);
out:
	return ret;
}
