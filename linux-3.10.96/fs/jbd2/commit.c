/*
 * linux/fs/jbd2/commit.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Journal commit routines for the generic filesystem journaling code;
 * part of the ext2fs journaling system.
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/jiffies.h>
#include <linux/crc32.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/bitops.h>
#include <trace/events/jbd2.h>

/*
 * Default IO end handler for temporary BJ_IO buffer_heads.
 */
static void journal_end_buffer_io_sync(struct buffer_head *bh, int uptodate)
{
	BUFFER_TRACE(bh, "");
	if (uptodate)
		set_buffer_uptodate(bh);
	else
		clear_buffer_uptodate(bh);
	unlock_buffer(bh);
}

/*
 * When an ext4 file is truncated, it is possible that some pages are not
 * successfully freed, because they are attached to a committing transaction.
 * After the transaction commits, these pages are left on the LRU, with no
 * ->mapping, and with attached buffers.  These pages are trivially reclaimable
 * by the VM, but their apparent absence upsets the VM accounting, and it makes
 * the numbers in /proc/meminfo look odd.
 *
 * So here, we have a buffer which has just come off the forget list.  Look to
 * see if we can strip all buffers from the backing page.
 *
 * Called under lock_journal(), and possibly under journal_datalist_lock.  The
 * caller provided us with a ref against the buffer, and we drop that here.
 */
static void release_buffer_page(struct buffer_head *bh)
{
	struct page *page;

	if (buffer_dirty(bh))
		goto nope;
	if (atomic_read(&bh->b_count) != 1)
		goto nope;
	page = bh->b_page;
	if (!page)
		goto nope;
	if (page->mapping)
		goto nope;

	/* OK, it's a truncated page */
	if (!trylock_page(page))
		goto nope;

	page_cache_get(page);
	__brelse(bh);
	try_to_free_buffers(page);
	unlock_page(page);
	page_cache_release(page);
	return;

nope:
	__brelse(bh);
}

static void jbd2_commit_block_csum_set(journal_t *j,
				       struct journal_head *descriptor)
{
	struct commit_header *h;
	__u32 csum;

	if (!JBD2_HAS_INCOMPAT_FEATURE(j, JBD2_FEATURE_INCOMPAT_CSUM_V2))
		return;

	h = (struct commit_header *)(jh2bh(descriptor)->b_data);
	h->h_chksum_type = 0;
	h->h_chksum_size = 0;
	h->h_chksum[0] = 0;
	csum = jbd2_chksum(j, j->j_csum_seed, jh2bh(descriptor)->b_data,
			   j->j_blocksize);
	h->h_chksum[0] = cpu_to_be32(csum);
}

/*
 * Done it all: now submit the commit record.  We should have
 * cleaned up our previous buffers by now, so if we are in abort
 * mode we can now just skip the rest of the journal write
 * entirely.
 *
 * Returns 1 if the journal needs to be aborted or 0 on success
 */
//从journal->j_head上得到journal队列头保存的物理块号block，再得到对应bh，然后分配jh,bh与jh相互构成联系，并发送submit_bh发送bh
static int journal_submit_commit_record(journal_t *journal,
					transaction_t *commit_transaction,
					struct buffer_head **cbh,
					__u32 crc32_sum)
{
	struct journal_head *descriptor;
	struct commit_header *tmp;
	struct buffer_head *bh;
	int ret;
	struct timespec now = current_kernel_time();

	*cbh = NULL;

	if (is_journal_aborted(journal))
		return 0;
    
    //从journal->j_head上得到journal队列头保存的物理块号block，再得到对应bh，
    //然后分配jh,bh与jh相互构成联系并返回jh给descriptor
	descriptor = jbd2_journal_get_descriptor_buffer(journal);
	if (!descriptor)
		return 1;

	bh = jh2bh(descriptor);

	tmp = (struct commit_header *)bh->b_data;
    //对descriptor这个journal描述符块的bh内存赋值，
	tmp->h_magic = cpu_to_be32(JBD2_MAGIC_NUMBER);
    //JBD2_COMMIT_BLOCK应该表示这个jh是一个record记录块
	tmp->h_blocktype = cpu_to_be32(JBD2_COMMIT_BLOCK);
	tmp->h_sequence = cpu_to_be32(commit_transaction->t_tid);
	tmp->h_commit_sec = cpu_to_be64(now.tv_sec);
	tmp->h_commit_nsec = cpu_to_be32(now.tv_nsec);

	if (JBD2_HAS_COMPAT_FEATURE(journal,
				    JBD2_FEATURE_COMPAT_CHECKSUM)) {
		tmp->h_chksum_type 	= JBD2_CRC32_CHKSUM;
		tmp->h_chksum_size 	= JBD2_CRC32_CHKSUM_SIZE;
        //journal描述符块的校验值
		tmp->h_chksum[0] 	= cpu_to_be32(crc32_sum);
	}
	jbd2_commit_block_csum_set(journal, descriptor);

	JBUFFER_TRACE(descriptor, "submit commit block");
    //传输之前锁定bh,之后在传输完成回调函数journal_end_buffer_io_sync，unlock_buffer(bh)解除锁定
	lock_buffer(bh);
	clear_buffer_dirty(bh);
	set_buffer_uptodate(bh);
	bh->b_end_io = journal_end_buffer_io_sync;

    //发送bh传输，这是journal日志文件里的物理块，每一次journal元数据传输最后要发送的record记录块
	if (journal->j_flags & JBD2_BARRIER &&
	    !JBD2_HAS_INCOMPAT_FEATURE(journal,
				       JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT))
		ret = submit_bh(WRITE_SYNC | WRITE_FLUSH_FUA, bh);
	else
		ret = submit_bh(WRITE_SYNC, bh);

	*cbh = bh;
	return ret;
}

/*
 * This function along with journal_submit_commit_record
 * allows to write the commit record asynchronously.
 */
static int journal_wait_on_commit_record(journal_t *journal,
					 struct buffer_head *bh)
{
	int ret = 0;

	clear_buffer_dirty(bh);
	wait_on_buffer(bh);

	if (unlikely(!buffer_uptodate(bh)))
		ret = -EIO;
	put_bh(bh);            /* One for getblk() */
	jbd2_journal_put_journal_head(bh2jh(bh));

	return ret;
}

/*
 * write the filemap data using writepage() address_space_operations.
 * We don't do block allocation here even for delalloc. We don't
 * use writepages() because with dealyed allocation we may be doing
 * block allocation in writepages().
 */
//这是把文件数据page cache 刷回磁盘
static int journal_submit_inode_data_buffers(struct address_space *mapping)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode =  WB_SYNC_ALL,
		.nr_to_write = mapping->nrpages * 2,
		.range_start = 0,
		.range_end = i_size_read(mapping->host),
	};
    //cache page脏页刷回硬盘
	ret = generic_writepages(mapping, &wbc);
	return ret;
}

/*
 * Submit all the data buffers of inode associated with the transaction to
 * disk.
 *
 * We are in a committing transaction. Therefore no new inode can be added to
 * our inode list. We use JI_COMMIT_RUNNING flag to protect inode we currently
 * operate on from being released while we write out pages.
 */
//这是把文件数据page cache 刷回磁盘，奇怪，jbd也处理文件数据呀，不只是处理inode元数据
static int journal_submit_data_buffers(journal_t *journal,
		transaction_t *commit_transaction)
{
	struct jbd2_inode *jinode;
	int err, ret = 0;
	struct address_space *mapping;

	spin_lock(&journal->j_list_lock);
    //一次取出transaction->t_inode_list链表上的struct jbd2_inode
	list_for_each_entry(jinode, &commit_transaction->t_inode_list, i_list) {
        //struct jbd2_inode上的struct inode的struct address_space
		mapping = jinode->i_vfs_inode->i_mapping;
		set_bit(__JI_COMMIT_RUNNING, &jinode->i_flags);
		spin_unlock(&journal->j_list_lock);
		/*
		 * submit the inode data buffers. We use writepage
		 * instead of writepages. Because writepages can do
		 * block allocation  with delalloc. We need to write
		 * only allocated blocks here.
		 */
		trace_jbd2_submit_inode_data(jinode->i_vfs_inode);
        //这是把文件数据page cache 刷回磁盘，奇怪，jbd也处理文件数据呀，不只是处理inode元数据
		err = journal_submit_inode_data_buffers(mapping);
		if (!ret)
			ret = err;
		spin_lock(&journal->j_list_lock);
		J_ASSERT(jinode->i_transaction == commit_transaction);
		clear_bit(__JI_COMMIT_RUNNING, &jinode->i_flags);
		smp_mb__after_clear_bit();
		wake_up_bit(&jinode->i_flags, __JI_COMMIT_RUNNING);
	}
	spin_unlock(&journal->j_list_lock);
	return ret;
}

/*
 * Wait for data submitted for writeout, refile inodes to proper
 * transaction if needed.
 *
 */
static int journal_finish_inode_data_buffers(journal_t *journal,
		transaction_t *commit_transaction)
{
	struct jbd2_inode *jinode, *next_i;
	int err, ret = 0;

	/* For locking, see the comment in journal_submit_data_buffers() */
	spin_lock(&journal->j_list_lock);
	list_for_each_entry(jinode, &commit_transaction->t_inode_list, i_list) {
		set_bit(__JI_COMMIT_RUNNING, &jinode->i_flags);
		spin_unlock(&journal->j_list_lock);
		err = filemap_fdatawait(jinode->i_vfs_inode->i_mapping);//等待数据传输完成
		if (err) {
			/*
			 * Because AS_EIO is cleared by
			 * filemap_fdatawait_range(), set it again so
			 * that user process can get -EIO from fsync().
			 */
			set_bit(AS_EIO,
				&jinode->i_vfs_inode->i_mapping->flags);

			if (!ret)
				ret = err;
		}
		spin_lock(&journal->j_list_lock);
		clear_bit(__JI_COMMIT_RUNNING, &jinode->i_flags);
		smp_mb__after_clear_bit();
		wake_up_bit(&jinode->i_flags, __JI_COMMIT_RUNNING);
	}

	/* Now refile inode to proper lists */
	list_for_each_entry_safe(jinode, next_i,
				 &commit_transaction->t_inode_list, i_list) {
		list_del(&jinode->i_list);
		if (jinode->i_next_transaction) {
			jinode->i_transaction = jinode->i_next_transaction;
			jinode->i_next_transaction = NULL;
			list_add(&jinode->i_list,
				&jinode->i_transaction->t_inode_list);
		} else {
			jinode->i_transaction = NULL;
		}
	}
	spin_unlock(&journal->j_list_lock);

	return ret;
}

static __u32 jbd2_checksum_data(__u32 crc32_sum, struct buffer_head *bh)
{
	struct page *page = bh->b_page;
	char *addr;
	__u32 checksum;

	addr = kmap_atomic(page);
	checksum = crc32_be(crc32_sum,
		(void *)(addr + offset_in_page(bh->b_data)), bh->b_size);
	kunmap_atomic(addr);

	return checksum;
}

static void write_tag_block(int tag_bytes, journal_block_tag_t *tag,
				   unsigned long long block)
{
	tag->t_blocknr = cpu_to_be32(block & (u32)~0);
	if (tag_bytes > JBD2_TAG_SIZE32)
		tag->t_blocknr_high = cpu_to_be32((block >> 31) >> 1);
}

static void jbd2_descr_block_csum_set(journal_t *j,
				      struct journal_head *descriptor)
{
	struct jbd2_journal_block_tail *tail;
	__u32 csum;

	if (!JBD2_HAS_INCOMPAT_FEATURE(j, JBD2_FEATURE_INCOMPAT_CSUM_V2))
		return;

	tail = (struct jbd2_journal_block_tail *)
			(jh2bh(descriptor)->b_data + j->j_blocksize -
			sizeof(struct jbd2_journal_block_tail));
	tail->t_checksum = 0;
	csum = jbd2_chksum(j, j->j_csum_seed, jh2bh(descriptor)->b_data,
			   j->j_blocksize);
    //计算checksum值
	tail->t_checksum = cpu_to_be32(csum);
}

static void jbd2_block_tag_csum_set(journal_t *j, journal_block_tag_t *tag,
				    struct buffer_head *bh, __u32 sequence)
{
	struct page *page = bh->b_page;
	__u8 *addr;
	__u32 csum;

	if (!JBD2_HAS_INCOMPAT_FEATURE(j, JBD2_FEATURE_INCOMPAT_CSUM_V2))
		return;

	sequence = cpu_to_be32(sequence);
	addr = kmap_atomic(page);
	csum = jbd2_chksum(j, j->j_csum_seed, (__u8 *)&sequence,
			  sizeof(sequence));
	csum = jbd2_chksum(j, csum, addr + offset_in_page(bh->b_data),
			  bh->b_size);
	kunmap_atomic(addr);

	tag->t_checksum = cpu_to_be32(csum);
}
/*
 * jbd2_journal_commit_transaction
 *
 * The primary function for committing a transaction to the log.  This
 * function is called by the journal thread to begin a complete commit.
 */
/*
在jbd2_journal_commit_transaction函数的while (commit_transaction->t_buffers)的那个循环，从commit_transaction->t_buffers链表取出本次备份的inode元数据的jh
jbd2_journal_get_descriptor_buffer->jbd2_journal_next_log_block 从journal->j_head++
得到一个journal日志文件分区的物理块号，比如说是1，然后得到该物理块的bh，命名为bh_head，header = (journal_header_t *)&bh->b_data[0]，
这个物理块bh内存地址开头是journal_header_t结构， tagp = &bh->b_data[sizeof(journal_header_t)]，bh往后的内存是journal_block_tag_t
结构，这个结构的t_blocknr成员保存本次备份的元数据inode在ext4文件系统的物理块号，journal_block_tag_t有多个，一个journal_block_tag_t
保存一个inode元数据的信息。接着wbuf[bufs++] = bh_head。接着执行 jbd2_journal_next_log_block() 再从journal->j_head得到一个journal日志文件分区的物理块号，
比如是2，保存到blocknr，这个物理块可是journal日志文件分区保存这个inode元数据的
，还执行jbd2_journal_write_metadata_buffer(....&new_jh, blocknr),令new_bh->b_blocknr = blocknr，new_bh指向的内存保存了本次本分的
一个inode元数据，命名为new_bh_1，接着wbuf[bufs++] = jh2bh(new_jh)，保存new_bh_1。再接着，tag = (journal_block_tag_t *) tagp;
write_tag_block(tag_bytes, tag, jh2bh(jh)->b_blocknr)，令 tag->t_blocknr = jh2bh(jh)->b_blocknr，这就是前边说的，journal_block_tag_t结构的
t_blocknr成员保存了本次journal日志文件分区备份的一个元数据inode的在ext4文件系统的物理块号。

然后继续while (commit_transaction->t_buffers)循环，从commit_transaction->t_buffers链表取出本次备份的第二个inode元数据的jh，
执行jbd2_journal_next_log_block()从从journal->j_head++得到该inode在journal日志文件分区
备份元数据的物理块号，比如是3，对应的new_bh_2，接着wbuf[bufs++] = jh2bh(new_jh)保存new_bh_2。然后再tag = (journal_block_tag_t *) tagp指向
下一个journal_block_tag_t，tag->t_blocknr = jh2bh(jh)->b_blocknr保存第二个inode元数据在ext4文件系统的物理块号。...............

接着执行 jbd2_journal_get_log_tail(journal, &first_tid, &first_block)，由于这是第一次执行jbd2_journal_commit_transaction()函数，
journal->j_checkpoint_transactions为NULL，则first_tid = 本次commit transaction的tid，first_block = 本次commit的transactions的t_log_start
这个t_log_start在jbd2_journal_commit_transaction函数开头被赋值为journal->j_head，即journal分区的第一个物理块号1。

总结：journal日志文件分区的第一个物理块，保存的数据格式是:一个journal_header_t+N个journal_block_tag_t，一个journal_block_tag_t对应一个备份的
inode元数据，尤其是journal_block_tag_t的t_blocknr成员保存inode在ext4文件系统的物理块号。然后journal日志文件分区的第2个物理块、第3个物理块........
分别用来备份第1个inode元数据，第2个inode元数据。这是第一个执行jbd2_journal_commit_transaction函数，如果下次执行到，有新的元数据备份，就执行
jbd2_journal_get_descriptor_buffer->jbd2_journal_next_log_block 从journal->j_head++得到journal日志文件分区的物理块号4，这个物理块保存本次的
一个journal_header_t+N个journal_block_tag_t，然后执行 jbd2_journal_next_log_block 从从journal->j_head++得到journal日志文件分区的物理块号5，
这个物理块保存本次的inode元数据，类推。

然后接着执行jbd2_journal_commit_transaction函数到最后，__jbd2_journal_insert_checkpoint()，把已经备份到journal日志文件分区的jh添加到，就是上边的new_bh_1那些对应的jh
本次 commit 的transaction->t_checkpoint_list链表。接着执行if (journal->j_checkpoint_transactions == NULL)那里，把本次的commit_transaction
插入到journal->j_checkpoint_transactions指向的transaction链表。这

接着等下次执行jbd2_journal_commit_transaction()，首先执行到__jbd2_journal_clean_checkpoint_list()，遍历journal->j_checkpoint_transactions上所有的transaction
，然后再取出transaction->t_checkpoint_list链表上所有的jh，如果该jh对应的inode元数据，已经刷入到了ext4文件系统，就把这个对应的jh和transaction释放掉。如果
journal->j_checkpoint_transactions上所有的transaction的所有的jh对应的inode元数据都刷回ext4文件系统了，那journal->j_checkpoint_transactions=NULL。否则，
journal->j_checkpoint_transactions就指向老的已经commit过的transaction，不为NULL。接着执行jbd2_journal_get_log_tail(journal, &first_tid, &first_block)
如果journal->j_checkpoint_transactions不是NULL(除了第一次commit，之后journal->j_checkpoint_transactions都不是NULL)，那first_tid = journal->j_checkpoint_transactions
first_block = journal->j_checkpoint_transactions->t_log_start，t_log_start在第一个transactions在刚开始执行jbd2_journal_commit_transaction()被赋值为journal->j_head，
就是前边的1。first_block就是上一次执行jbd2_journal_commit_transaction()时，commit transaction用的第一个journal分区的的物理块号，如果有多次commit，first_block应该是
最老的那个transaction分配在journal分区分配的的第一个物理块号，first_tid 是最老的那个transaction的tid，接着往后走，有概率执行到jbd2_update_log_tail(journal, first_tid, first_block)
把sb->s_sequence和journal->j_tail_sequence被赋值为first_tid，即最老的transaction的tid，journal->j_tail和sb->s_start被赋值为first_block，即最老的transactions在journal分区的分配的
第一个物理块号。我认为，journal->j_tail和journal->j_head，从jouranl日志文件分区分配空闲物理块号用journal->j_head，然后journal->j_tail++，指向下一个物理块号，journal->j_tail是当
jouranl备份元数据用的物理块被释放了，空闲物理快吧，不对，journal->j_tail-journal->j_first之前的物理块时空闲的，transaction使用后释放掉的???????????????

*/
void jbd2_journal_commit_transaction(journal_t *journal)
{
	struct transaction_stats_s stats;
	transaction_t *commit_transaction;
	struct journal_head *jh, *new_jh, *descriptor;
	struct buffer_head **wbuf = journal->j_wbuf;
	int bufs;
	int flags;
	int err;
	unsigned long long blocknr;
	ktime_t start_time;
	u64 commit_time;
	char *tagp = NULL;
	journal_header_t *header;
	journal_block_tag_t *tag = NULL;
	int space_left = 0;
	int first_tag = 0;
	int tag_flag;
	int i;
	int tag_bytes = journal_tag_bytes(journal);
	struct buffer_head *cbh = NULL; /* For transactional checksums */
	__u32 crc32_sum = ~0;
	struct blk_plug plug;
	/* Tail of the journal */
	unsigned long first_block;
	tid_t first_tid;
	int update_tail;
	int csum_size = 0;

	if (JBD2_HAS_INCOMPAT_FEATURE(journal, JBD2_FEATURE_INCOMPAT_CSUM_V2))
		csum_size = sizeof(struct jbd2_journal_block_tail);

	/*
	 * First job: lock down the current transaction and wait for
	 * all outstanding updates to complete.
	 */

	/* Do we need to erase the effects of a prior jbd2_journal_flush? */
	if (journal->j_flags & JBD2_FLUSHED) {
		jbd_debug(3, "super block updated\n");
		mutex_lock(&journal->j_checkpoint_mutex);
		/*
		 * We hold j_checkpoint_mutex so tail cannot change under us.
		 * We don't need any special data guarantees for writing sb
		 * since journal is empty and it is ok for write to be
		 * flushed only with transaction commit.
		 */
		jbd2_journal_update_sb_log_tail(journal,
						journal->j_tail_sequence,
						journal->j_tail,
						WRITE_SYNC);
		mutex_unlock(&journal->j_checkpoint_mutex);
	} else {
		jbd_debug(3, "superblock not updated\n");
	}

	J_ASSERT(journal->j_running_transaction != NULL);
	J_ASSERT(journal->j_committing_transaction == NULL);

    //获取journal上的transaction
	commit_transaction = journal->j_running_transaction;
	J_ASSERT(commit_transaction->t_state == T_RUNNING);

	trace_jbd2_start_commit(journal, commit_transaction);
	jbd_debug(1, "JBD2: starting commit of transaction %d\n",
			commit_transaction->t_tid);

	write_lock(&journal->j_state_lock);
    //transaction->t_state设置为T_LOCKED，锁住后就不能再添加新的transaction??????????????????????
	commit_transaction->t_state = T_LOCKED;

	trace_jbd2_commit_locking(journal, commit_transaction);
	stats.run.rs_wait = commit_transaction->t_max_wait;
	stats.run.rs_request_delay = 0;
	stats.run.rs_locked = jiffies;
	if (commit_transaction->t_requested)
		stats.run.rs_request_delay =
			jbd2_time_diff(commit_transaction->t_requested,
				       stats.run.rs_locked);
	stats.run.rs_running = jbd2_time_diff(commit_transaction->t_start,
					      stats.run.rs_locked);

	spin_lock(&commit_transaction->t_handle_lock);
    //如果transaction->t_updates不为0，说明提交journal的transaction的那个进程，jbd提交过程还没走完，只执行了
    //jbd2_journal_start令transaction->t_updates加1，没有执行jbd2_journal_stop()最后的代码令transaction->t_updates减1。
    //所以这个jbd commit进程要先在这里journal->j_wait_updates上休眠，等待刚才那个进程执行jbd2_journal_stop()，
    //transaction->t_updates减1，然后wake_up在journal->j_wait_updates上休眠的jbd commit进程
	while (atomic_read(&commit_transaction->t_updates)) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_updates, &wait,
					TASK_UNINTERRUPTIBLE);
		if (atomic_read(&commit_transaction->t_updates)) {
			spin_unlock(&commit_transaction->t_handle_lock);
			write_unlock(&journal->j_state_lock);
			schedule();
			write_lock(&journal->j_state_lock);
			spin_lock(&commit_transaction->t_handle_lock);
		}
		finish_wait(&journal->j_wait_updates, &wait);
	}
	spin_unlock(&commit_transaction->t_handle_lock);

	J_ASSERT (atomic_read(&commit_transaction->t_outstanding_credits) <=
			journal->j_max_transaction_buffers);

	/*
	 * First thing we are allowed to do is to discard any remaining
	 * BJ_Reserved buffers.  Note, it is _not_ permissible to assume
	 * that there are no such buffers: if a large filesystem
	 * operation like a truncate needs to split itself over multiple
	 * transactions, then it may try to do a jbd2_journal_restart() while
	 * there are still BJ_Reserved buffers outstanding.  These must
	 * be released cleanly from the current transaction.
	 *
	 * In this case, the filesystem must still reserve write access
	 * again before modifying the buffer in the new transaction, but
	 * we do not require it to remember exactly which old buffers it
	 * has reserved.  This is consistent with the existing behaviour
	 * that multiple jbd2_journal_get_write_access() calls to the same
	 * buffer are perfectly permissible.
	 */
	while (commit_transaction->t_reserved_list) {
        //t_reserved_list队列上的jh是transaction添加的但是没有标记脏的
        //一个jh先执行jbd2_journal_get_write_access()被添加到transaction的BJ_Reserved即t_reserved_list链表
        //然后会执行__ext4_handle_dirty_metadata()被添加到transaction的BJ_Metadata链表，这时表示这个jh对应的bh的元数据
        //已经被修改了，是脏bh。但是如果这个时候transaction->t_reserved_list即BJ_Reserved链表上还有jh，就说明这个jh
        //对应的元数据还没有被修改，那本次不用处理这个jh了,
        //这种情况会发生吗????????????????????????????????????????????????????
		jh = commit_transaction->t_reserved_list;
		JBUFFER_TRACE(jh, "reserved, unused: refile");
		/*
		 * A jbd2_journal_get_undo_access()+jbd2_journal_release_buffer() may
		 * leave undo-committed data.
		 */
		if (jh->b_committed_data) {
			struct buffer_head *bh = jh2bh(jh);

			jbd_lock_bh_state(bh);
			jbd2_free(jh->b_committed_data, bh->b_size);
			jh->b_committed_data = NULL;
			jbd_unlock_bh_state(bh);
		}
        //jh->b_next_transaction为NILL，jh没用则释放掉
        //否则要把jh再次添加到jh->b_next_transaction执行的BJ_Forget或BJ_Metadata或BJ_Reserved链表
		jbd2_journal_refile_buffer(journal, jh);
	}

	/*
	 * Now try to drop any written-back buffers from the journal's
	 * checkpoint lists.  We do this *before* commit because it potentially
	 * frees some memory
	 */
	spin_lock(&journal->j_list_lock);
    
 //遍历journal->j_checkpoint_transactions->t_checkpoint_list链表上所有的jh,如果jh对应的bh对应的inode等元数据是否刷回ext4文件系统了
 //则释放jh和jh所属的transaction结构，也就是说，一个jh在上一次执行过jbd2_journal_commit_transaction()最后，把该jh暂时放到
 //journal->j_checkpoint_transactions->t_checkpoint_list链表，等下次执行jbd2_journal_commit_transaction(),在这个函数开头，
 //执行__jbd2_journal_clean_checkpoint_list()。遍历journal->j_checkpoint_transactions->t_checkpoint_list链表上所有的jh，
 //jh对应inode元数据刷回ext4文件系统了，就释放这个jh和所属的transaction。那问题来了，当初把jh对应的inode元数据备份到journal
 //日志文件分区时，分配了日志描述符block head即journal_header_t，保存备份元数据inode在ext4文件系统的物理块号
 //的journal_block_tag_t，还有备份inode元数据的journal日志文件分区的一个物理块，什么时候释放掉????现在已经完成使命了，因为inode
 //元数据已经刷回ext4文件系统了。
	__jbd2_journal_clean_checkpoint_list(journal);
	spin_unlock(&journal->j_list_lock);

	jbd_debug(3, "JBD2: commit phase 1\n");

	/*
	 * Clear revoked flag to reflect there is no revoked buffers
	 * in the next transaction which is going to be started.
	 */
	 //????????????????????????????????????????????????????
	jbd2_clear_buffer_revoked_flags(journal);

	/*
	 * Switch to a new revoke table.
	 */
	 //????????????????????????????????????????????????????
	jbd2_journal_switch_revoke_table(journal);

	trace_jbd2_commit_flushing(journal, commit_transaction);
	stats.run.rs_flushing = jiffies;
	stats.run.rs_locked = jbd2_time_diff(stats.run.rs_locked,
					     stats.run.rs_flushing);
    //transaction->t_state设置成为T_FLUSH
	commit_transaction->t_state = T_FLUSH;
    //j_committing_transaction指向刚才那个commit_transaction
	journal->j_committing_transaction = commit_transaction;
    //journal->j_running_transaction设为NULL，
	journal->j_running_transaction = NULL;
	start_time = ktime_get();

    //commit_transaction->t_log_start被赋值为journal->j_head
	commit_transaction->t_log_start = journal->j_head;
    //唤醒journal->j_wait_transaction_locked上休眠的ext4 jbd进程，这些进程在执行jbd2_journal_start()时，因为
    //journal->j_running_transaction在jbd2_journal_commit_transaction()中设置为T_LOCKED而休眠
	wake_up(&journal->j_wait_transaction_locked);
	write_unlock(&journal->j_state_lock);

	jbd_debug(3, "JBD2: commit phase 2\n");

	/*
	 * Now start flushing things to disk, in the order they appear
	 * on the transaction lists.  Data blocks go first.
	 */
	//这里貌似完成是的ext4 数据块?????????
	//这是把文件数据page cache 刷回磁盘，奇怪，jbd也处理文件数据呀，不只是处理inode元数据
	//原来是在order模式下，要先把jh-->bh有关的Data blocks刷回磁盘，????Data blocks是什么鬼????????????????????不理解????????
	err = journal_submit_data_buffers(journal, commit_transaction);
	if (err)
		jbd2_journal_abort(journal, err);

	blk_start_plug(&plug);
    //????????????????????????????????????????????????????????????????????
	jbd2_journal_write_revoke_records(journal, commit_transaction,
					  WRITE_SYNC);
    //这里貌似会把本次的page cache提交到block层
	blk_finish_plug(&plug);

	jbd_debug(3, "JBD2: commit phase 2\n");

	/*
	 * Way to go: we have now written out all of the data for a
	 * transaction!  Now comes the tricky part: we need to write out
	 * metadata.  Loop over the transaction's entire buffer list:
	 */
	write_lock(&journal->j_state_lock);
    //transaction->t_state状态设置为T_COMMIT
	commit_transaction->t_state = T_COMMIT;
	write_unlock(&journal->j_state_lock);

	trace_jbd2_commit_logging(journal, commit_transaction);
	stats.run.rs_logging = jiffies;
	stats.run.rs_flushing = jbd2_time_diff(stats.run.rs_flushing,
					       stats.run.rs_logging);
	stats.run.rs_blocks =
		atomic_read(&commit_transaction->t_outstanding_credits);
	stats.run.rs_blocks_logged = 0;

	J_ASSERT(commit_transaction->t_nr_buffers <=
		 atomic_read(&commit_transaction->t_outstanding_credits));

	err = 0;
	descriptor = NULL;
	bufs = 0;
	blk_start_plug(&plug);
    //现在开始发送元数据
	while (commit_transaction->t_buffers) {

		/* Find the next buffer to be journaled... */
        //从transaction->t_buffers指向的元数据链表BJ_Metadata取出jh
		jh = commit_transaction->t_buffers;

		/* If we're in abort mode, we just un-journal the buffer and
		   release it. */

		if (is_journal_aborted(journal)) {
			clear_buffer_jbddirty(jh2bh(jh));
			JBUFFER_TRACE(jh, "journal is aborting: refile");
			jbd2_buffer_abort_trigger(jh,
						  jh->b_frozen_data ?
						  jh->b_frozen_triggers :
						  jh->b_triggers);
			jbd2_journal_refile_buffer(journal, jh);
			/* If that was the last one, we need to clean up
			 * any descriptor buffers which may have been
			 * already allocated, even if we are now
			 * aborting. */
			if (!commit_transaction->t_buffers)
				goto start_journal_io;
			continue;
		}

		/* Make sure we have a descriptor block in which to
		   record the metadata buffer. */
        //descriptor描述符块依次只分配一个，journal_header_t也只有一个，journal_block_tag_t有多个，每个journal_block_tag_t
        //对应一个备份的inode元数据
		if (!descriptor) {
			struct buffer_head *bh;

			J_ASSERT (bufs == 0);

			jbd_debug(4, "JBD2: get descriptor\n");
            //从ext4文件系统磁盘空间中取出的journal那部分空间文件的一个描述符块struct journal_head descriptor
			descriptor = jbd2_journal_get_descriptor_buffer(journal);
			if (!descriptor) {
				jbd2_journal_abort(journal, -EIO);
				continue;
			}
            //描述符块descriptor对应的bh，这个bh不是文件inode磁盘物理块对应的bh，是journal空间文件的一个bh
            //是备份文件inode数据的journal空间里的bh
			bh = jh2bh(descriptor);
			jbd_debug(4, "JBD2: got buffer %llu (%p)\n",
				(unsigned long long)bh->b_blocknr, bh->b_data);
            //header指向journal空间里的bh内存空间journal_header_t，journal描述符头
			header = (journal_header_t *)&bh->b_data[0];
            //显然这是journal描述符块的开头部分，h_magic，h_blocktype
			header->h_magic     = cpu_to_be32(JBD2_MAGIC_NUMBER);
			header->h_blocktype = cpu_to_be32(JBD2_DESCRIPTOR_BLOCK);
            //h_sequence记录了transaction->t_tid
			header->h_sequence  = cpu_to_be32(commit_transaction->t_tid);
            //tagp指向journal描述符块的bh内存首地址偏移journal_header_t大小后的空间
			tagp = &bh->b_data[sizeof(journal_header_t)];
            //space_left是bh代表的物理块大小减去journal_header_t大小后的
			space_left = bh->b_size - sizeof(journal_header_t);
			first_tag = 1;
			set_buffer_jwrite(bh);
			set_buffer_dirty(bh);
            //wbuf[]填充bh，这个bh是journal空间里的bh,备份文件inode脏数据的，不是文件inode的bh
			wbuf[bufs++] = bh;

			/* Record it so that we can wait for IO
                           completion later */
			BUFFER_TRACE(bh, "ph3: file as descriptor");
            //把journal日志描述符块对应的descriptor这个jh添加到commit_transaction的BJ_LogCtl链表
			jbd2_journal_file_buffer(descriptor, commit_transaction,
					BJ_LogCtl);
		}

		/* Where is the buffer to be written? */
        //下一个要写的物理块块号?????????这一步很关键，这个blocknr应该是journal空间文件范围的一个物理块号
        //下边分配new_jh和new_bh时，有new_bh->b_blocknr = blocknr，new_bh->b_blocknr是journal空间的，new_bh指向的内存数据
        //又是本次inode元数据，jbd备份inode元数据就是把new_bh内存数据保存journal空间的物理块，物理块号是blocknr
		err = jbd2_journal_next_log_block(journal, &blocknr);
		/* If the block mapping failed, just abandon the buffer
		   and repeat this loop: we'll fall into the
		   refile-on-abort condition above. */
		if (err) {
			jbd2_journal_abort(journal, err);
			continue;
		}

		/*
		 * start_this_handle() uses t_outstanding_credits to determine
		 * the free space in the log, but this counter is changed
		 * by jbd2_journal_next_log_block() also.
		 */
		atomic_dec(&commit_transaction->t_outstanding_credits);

		/* Bump b_count to prevent truncate from stumbling over
                   the shadowed buffer!  @@@ This can go if we ever get
                   rid of the BJ_IO/BJ_Shadow pairing of buffers. */
		atomic_inc(&jh2bh(jh)->b_count);

		/* Make a temporary IO buffer with which to write it out
                   (this will requeue both the metadata buffer and the
                   temporary IO buffer). new_bh goes on BJ_IO*/

		set_bit(BH_JWrite, &jh2bh(jh)->b_state);
		/*
		 * akpm: jbd2_journal_write_metadata_buffer() sets
		 * new_bh->b_transaction to commit_transaction.
		 * We need to clean this up before we release new_bh
		 * (which is of type BJ_IO)
		 */
		JBUFFER_TRACE(jh, "ph3: write metadata");
        //jh是从transaction的BJ_Metadata取出jh。根据jh分配新的new_jh，二者对应的bh数据一样，new_jh的new_bh被写入磁盘，
        //原有jh被移动到commit_transaction的BJ_Shadow链表，new_jh被移动到commit_transaction的BJ_IO链表。
        //new_bh内存指向的是文件inode元数据bh的内存，这就是文件inode元数据备份到journal空间的的核心数据呀
		flags = jbd2_journal_write_metadata_buffer(commit_transaction,
						      jh, &new_jh, blocknr);
		if (flags < 0) {
			jbd2_journal_abort(journal, flags);
			continue;
		}
        //设置new_jh的bh的b_state是BH_JWrite，表示该bh将要被写入磁盘?????????????
		set_bit(BH_JWrite, &jh2bh(new_jh)->b_state);
        //wbuf[bufs++]记录new_bh，下边submit_bh把new_bh写入journal空间的blocknr物理块号位置，完成inode元数据的备份!!!!!!!!!!
		wbuf[bufs++] = jh2bh(new_jh);

		/* Record the new block's tag in the current descriptor
                   buffer */

		tag_flag = 0;
		if (flags & 1)
			tag_flag |= JBD2_FLAG_ESCAPE;
		if (!first_tag)
			tag_flag |= JBD2_FLAG_SAME_UUID;
        //tagp在上边指向journal描述符块的bh内存首地址偏移journal_header_t大小后的空间，journal_block_tag_t应该就是描述符块
        //专有数据结构吧
		tag = (journal_block_tag_t *) tagp;
        
        //tag->t_blocknr记录jh的bh的物理块号!!!!!!!!!!!!!!!!!!!!!!!!!这是关键一步，记录inode这些元数据所在bh对应的物理块的
        //块号，journal_block_tag_t记录inode元数据所在物理块号，将来从journal日志分区恢复时，得先知道journal里保存的inode元数据的在ext4文件系统的物理块号
        //注意，jh这是代表inode元数据的jh的，不是journal描述符块的bh，什么鬼，乱七八糟的!!!!!!!!!!!!!!!!!!
		write_tag_block(tag_bytes, tag, jh2bh(jh)->b_blocknr);//即tag->t_blocknr = jh2bh(jh)->b_blocknr;
		tag->t_flags = cpu_to_be16(tag_flag);
		jbd2_block_tag_csum_set(journal, tag, jh2bh(new_jh),
					commit_transaction->t_tid);
        //tagp继续向后偏移tag_bytes
		tagp += tag_bytes;
		space_left -= tag_bytes;
        //inode元数据传输时的第一个journal描述符块first_tag被置1
		if (first_tag) {
            //tagp指向的16字节内存空间设置成j_uuid
			memcpy (tagp, journal->j_uuid, 16);
			tagp += 16;
			space_left -= 16;
			first_tag = 0;
		}

		/* If there's no more to do, or if the descriptor is full,
		   let the IO rip! */
        //wbuf[bufs++]保存的要传输的bh格式达到journal->j_wbufsize，或者transaction->t_buffers即BJ_Metadata链表空了
        //或者journal描述符块对应的bh空间块满了，就开始启动submit_bh
		if (bufs == journal->j_wbufsize ||
		    commit_transaction->t_buffers == NULL ||
		    space_left < tag_bytes + 16 + csum_size) {

			jbd_debug(4, "JBD2: Submit %d IOs\n", bufs);

			/* Write an end-of-descriptor marker before
                           submitting the IOs.  "tag" still points to
                           the last tag we set up. */

			tag->t_flags |= cpu_to_be16(JBD2_FLAG_LAST_TAG);
            //计算jh2bh(descriptor)->b_data的checksum值
			jbd2_descr_block_csum_set(journal, descriptor);
start_journal_io:
			for (i = 0; i < bufs; i++) {
				struct buffer_head *bh = wbuf[i];
				/*
				 * Compute checksum.
				 */
				if (JBD2_HAS_COMPAT_FEATURE(journal,
					JBD2_FEATURE_COMPAT_CHECKSUM)) {
					crc32_sum =
					    jbd2_checksum_data(crc32_sum, bh);
				}

				lock_buffer(bh);
				clear_buffer_dirty(bh);
				set_buffer_uptodate(bh);
				bh->b_end_io = journal_end_buffer_io_sync;
                //看这样在这里发起实际的bh数据传输
				submit_bh(WRITE_SYNC, bh);
			}
			cond_resched();
			stats.run.rs_blocks_logged += bufs;

			/* Force a new descriptor to be generated next
                           time round the loop. */
			descriptor = NULL;
			bufs = 0;
		}
	}

    //等待ommit_transaction->t_inode_list上数据传输完成,这是等待文件数据write back完成??????????????????????????? 
	err = journal_finish_inode_data_buffers(journal, commit_transaction);
	if (err) {
		printk(KERN_WARNING
			"JBD2: Detected IO errors while flushing file data "
		       "on %s\n", journal->j_devname);
		if (journal->j_flags & JBD2_ABORT_ON_SYNCDATA_ERR)
			jbd2_journal_abort(journal, err);
		err = 0;
	}

	/*
	 * Get current oldest transaction in the log before we issue flush
	 * to the filesystem device. After the flush we can be sure that
	 * blocks of all older transactions are checkpointed to persistent
	 * storage and we will be safe to update journal start in the
	 * superblock with the numbers we get here.
	 */
//一般情况是从journal->j_checkpoint_transactions或者journal->j_committing_transaction得到transaction->t_tid和transaction->t_log_start
//赋值给first_tid和first_block。first_block本质上来自journal->j_head。如果transaction->t_tid比journal->j_tail_sequence大返回1.
	update_tail =
		jbd2_journal_get_log_tail(journal, &first_tid, &first_block);

	write_lock(&journal->j_state_lock);
	if (update_tail) {
		long freed = first_block - journal->j_tail;

		if (first_block < journal->j_tail)
			freed += journal->j_last - journal->j_first;
		/* Update tail only if we free significant amount of space */
		if (freed < journal->j_maxlen / 4)//看样子
			update_tail = 0;//在这里update_tail修改为0，就不再执行下边的jbd2_update_log_tail了
	}
	J_ASSERT(commit_transaction->t_state == T_COMMIT);
    //commit_transaction->t_state 状态设置成 T_COMMIT_DFLUSH
	commit_transaction->t_state = T_COMMIT_DFLUSH;
	write_unlock(&journal->j_state_lock);

	/* 
	 * If the journal is not located on the file system device,
	 * then we must flush the file system device before we issue
	 * the commit record
	 */
	if (commit_transaction->t_need_data_flush &&
	    (journal->j_fs_dev != journal->j_dev) &&
	    (journal->j_flags & JBD2_BARRIER))
		blkdev_issue_flush(journal->j_fs_dev, GFP_NOFS, NULL);

	/* Done it all: now write the commit record asynchronously. */
    //同步写一个记录快
	if (JBD2_HAS_INCOMPAT_FEATURE(journal,
				      JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)) {
		//从journal->j_head上得到journal队列头保存的物理块号block，再得到对应bh，
		//然后分配jh,bh与jh相互构成联系，并发送submit_bh发送bh
		err = journal_submit_commit_record(journal, commit_transaction,
						 &cbh, crc32_sum);
		if (err)
			__jbd2_journal_abort_hard(journal);
	}
    //这个函数 最终调用 mmc_request_fn 发送emmc命令给emmc控制器，SAS磁盘也是这个流程
	blk_finish_plug(&plug);

	/* Lo and behold: we have just managed to send a transaction to
           the log.  Before we can commit it, wait for the IO so far to
           complete.  Control buffers being written are on the
           transaction's t_log_list queue, and metadata buffers are on
           the t_iobuf_list queue.

	   Wait for the buffers in reverse order.  That way we are
	   less likely to be woken up until all IOs have completed, and
	   so we incur less scheduling load.
	*/

	jbd_debug(3, "JBD2: commit phase 3\n");

	/*
	 * akpm: these are BJ_IO, and j_list_lock is not needed.
	 * See __journal_try_to_free_buffer.
	 */
wait_for_iobuf:
	while (commit_transaction->t_iobuf_list != NULL) {
		struct buffer_head *bh;
        //从commit_transaction->t_iobuf_list即BJ_IO链表取出bh
		jh = commit_transaction->t_iobuf_list->b_tprev;
		bh = jh2bh(jh);
        //如果bh是锁定的，说明正在传输
		if (buffer_locked(bh)) {
			wait_on_buffer(bh);//等待bh对应page数据传输完成
			//bh传输完成后，接着调到wait_for_iobuf等待下一个jh
			goto wait_for_iobuf;
		}
		if (cond_resched())
			goto wait_for_iobuf;

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		clear_buffer_jwrite(bh);

		JBUFFER_TRACE(jh, "ph4: unfile after journal write");
        //从BJ_IO这个链表中移除jh，释放jh占用的内存空间,这个jh没用了
		jbd2_journal_unfile_buffer(journal, jh);

		/*
		 * ->t_iobuf_list should contain only dummy buffer_heads
		 * which were created by jbd2_journal_write_metadata_buffer().
		 */
		BUFFER_TRACE(bh, "dumping temporary bh");
		jbd2_journal_put_journal_head(jh);
		__brelse(bh);
		J_ASSERT_BH(bh, atomic_read(&bh->b_count) == 0);
        //释放bh
		free_buffer_head(bh);

		/* We also have to unlock and free the corresponding
                   shadowed buffer */
        //从commit_transaction->t_shadow_list即BJ_Shadow链表取出bh
		jh = commit_transaction->t_shadow_list->b_tprev;
		bh = jh2bh(jh);
		clear_bit(BH_JWrite, &bh->b_state);
		J_ASSERT_BH(bh, buffer_jbddirty(bh));

		/* The metadata is now released for reuse, but we need
                   to remember it against this transaction so that when
                   we finally commit, we can do any checkpointing
                   required. */
		JBUFFER_TRACE(jh, "file as BJ_Forget");
        //把从BJ_Shadow链表取出jh移动到BJ_Forget链表，前边的jbd2_journal_write_metadata_buffer执行时，同样的两份jh，一个
        //加到BJ_IO链表，一个加到BJ_Shadow链表，BJ_IO链表上的jh前几行已经被剔除掉，现在BJ_Shadow上的jh要添加到BJ_Forget链表
        //这样做的目的是，后边checkpoint时要处理BJ_Forget队列上的jh
		jbd2_journal_file_buffer(jh, commit_transaction, BJ_Forget);
		/*
		 * Wake up any transactions which were waiting for this IO to
		 * complete. The barrier must be here so that changes by
		 * jbd2_journal_file_buffer() take effect before wake_up_bit()
		 * does the waitqueue check.
		 */
		smp_mb();
        //唤醒等待BH_Unshadow链表上IO传输完成的transactions
		wake_up_bit(&bh->b_state, BH_Unshadow);
		JBUFFER_TRACE(jh, "brelse shadowed buffer");
		__brelse(bh);
	}

	J_ASSERT (commit_transaction->t_shadow_list == NULL);

	jbd_debug(3, "JBD2: commit phase 4\n");

	/* Here we wait for the revoke record and descriptor record buffers */
 wait_for_ctlbuf:
	while (commit_transaction->t_log_list != NULL) {
		struct buffer_head *bh;
        //取出transaction上BJ_LogCtl链表的jh，
        //该函数开头把journal日志描述符块对应的descriptor这个jh添加到commit_transaction的BJ_LogCtl链表，显然这是等
        //journal日志描述符块对应的descriptor的这个jh传输完成，圆满
		jh = commit_transaction->t_log_list->b_tprev;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) {
			wait_on_buffer(bh);
			goto wait_for_ctlbuf;
		}
		if (cond_resched())
			goto wait_for_ctlbuf;

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		BUFFER_TRACE(bh, "ph5: control buffer writeout done: unfile");
		clear_buffer_jwrite(bh);
        //从这个链表中移除jh，释放jh有关占用的内存空间,这个jh没用了
		jbd2_journal_unfile_buffer(journal, jh);
		jbd2_journal_put_journal_head(jh);
		__brelse(bh);		/* One for getblk */
		/* AKPM: bforget here */
	}

	if (err)
		jbd2_journal_abort(journal, err);

	jbd_debug(3, "JBD2: commit phase 5\n");
	write_lock(&journal->j_state_lock);
	J_ASSERT(commit_transaction->t_state == T_COMMIT_DFLUSH);
	commit_transaction->t_state = T_COMMIT_JFLUSH;
	write_unlock(&journal->j_state_lock);

    //又同步写一个记录块，就是JBD2_COMMIT_BLOCK ,这与前边的属性不一样!!!!!!!!!!!!!!!!
	if (!JBD2_HAS_INCOMPAT_FEATURE(journal,
				       JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)) {	    
        //从journal->j_head上得到journal队列头保存的物理块号block，再得到对应bh，然后分配jh,bh与jh相互构成联系，并发送submit_bh发送bh
		err = journal_submit_commit_record(journal, commit_transaction,
						&cbh, crc32_sum);
		if (err)
			__jbd2_journal_abort_hard(journal);
	}
	if (cbh)
		err = journal_wait_on_commit_record(journal, cbh);
 
	if (JBD2_HAS_INCOMPAT_FEATURE(journal,
				      JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT) &&
	    journal->j_flags & JBD2_BARRIER) {
		blkdev_issue_flush(journal->j_dev, GFP_NOFS, NULL);
	}

	if (err)
		jbd2_journal_abort(journal, err);

	/*
	 * Now disk caches for filesystem device are flushed so we are safe to
	 * erase checkpointed transactions from the log by updating journal
	 * superblock.
	 */
	//前边的jbd2_journal_get_log_tail()返回1，说明journal->j_tail_sequence需要更新，因为有比j_tail_sequence更大的commit
	//transaction id，journal->j_tail_sequence在jbd2_journal_commit_transaction()最后要记录最大的commit transaction id
	if (update_tail)
		jbd2_update_log_tail(journal, first_tid, first_block);

	/* End of a transaction!  Finally, we can do checkpoint
           processing: any buffers committed as a result of this
           transaction can be removed from any checkpoint list it was on
           before. */

	jbd_debug(3, "JBD2: commit phase 6\n");

	J_ASSERT(list_empty(&commit_transaction->t_inode_list));
	J_ASSERT(commit_transaction->t_buffers == NULL);
	J_ASSERT(commit_transaction->t_checkpoint_list == NULL);
	J_ASSERT(commit_transaction->t_iobuf_list == NULL);
	J_ASSERT(commit_transaction->t_shadow_list == NULL);
	J_ASSERT(commit_transaction->t_log_list == NULL);

restart_loop:
	/*
	 * As there are other places (journal_unmap_buffer()) adding buffers
	 * to this list we have to be careful and hold the j_list_lock.
	 */
	spin_lock(&journal->j_list_lock);
    //最后开始处理transaction->t_forget BJ_Forget链表上的jh,前边是把BJ_Shadow上的jh添加到BJ_Forget链表，这个jh对应的是inode
    //元数据的，前边已经把inode元数据备份到journal日志文件分区了，然后把对应的jh移动到BJ_Forget
	while (commit_transaction->t_forget) {
		transaction_t *cp_transaction;
		struct buffer_head *bh;
		int try_to_free = 0;
        //t_forget链表上的jh
		jh = commit_transaction->t_forget;
		spin_unlock(&journal->j_list_lock);
		bh = jh2bh(jh);
		/*
		 * Get a reference so that bh cannot be freed before we are
		 * done with it.
		 */
		get_bh(bh);
		jbd_lock_bh_state(bh);
		J_ASSERT_JH(jh,	jh->b_transaction == commit_transaction);

		/*
		 * If there is undo-protected committed data against
		 * this buffer, then we can remove it now.  If it is a
		 * buffer needing such protection, the old frozen_data
		 * field now points to a committed version of the
		 * buffer, so rotate that field to the new committed
		 * data.
		 *
		 * Otherwise, we can just throw away the frozen data now.
		 *
		 * We also know that the frozen data has already fired
		 * its triggers if they exist, so we can clear that too.
		 */
		if (jh->b_committed_data) {
			jbd2_free(jh->b_committed_data, bh->b_size);
			jh->b_committed_data = NULL;
			if (jh->b_frozen_data) {
				jh->b_committed_data = jh->b_frozen_data;
				jh->b_frozen_data = NULL;
				jh->b_frozen_triggers = NULL;
			}
		} else if (jh->b_frozen_data) {
			jbd2_free(jh->b_frozen_data, bh->b_size);
			jh->b_frozen_data = NULL;
			jh->b_frozen_triggers = NULL;
		}

		spin_lock(&journal->j_list_lock);
        //jh对应的transaction之前已经被添加到了checkpointed的transaction链表?????????????
		cp_transaction = jh->b_cp_transaction;
		if (cp_transaction) {
			JBUFFER_TRACE(jh, "remove from old cp transaction");
			cp_transaction->t_chp_stats.cs_dropped++;
			__jbd2_journal_remove_checkpoint(jh);
		}

		/* Only re-checkpoint the buffer_head if it is marked
		 * dirty.  If the buffer was added to the BJ_Forget list
		 * by jbd2_journal_forget, it may no longer be dirty and
		 * there's no point in keeping a checkpoint record for
		 * it. */

		/*
		* A buffer which has been freed while still being journaled by
		* a previous transaction.
		*/
	    //bh已经被释放了??
		if (buffer_freed(bh)) {
			/*
			 * If the running transaction is the one containing
			 * "add to orphan" operation (b_next_transaction !=
			 * NULL), we have to wait for that transaction to
			 * commit before we can really get rid of the buffer.
			 * So just clear b_modified to not confuse transaction
			 * credit accounting and refile the buffer to
			 * BJ_Forget of the running transaction. If the just
			 * committed transaction contains "add to orphan"
			 * operation, we can completely invalidate the buffer
			 * now. We are rather through in that since the
			 * buffer may be still accessible when blocksize <
			 * pagesize and it is attached to the last partial
			 * page.
			 */
			jh->b_modified = 0;
			if (!jh->b_next_transaction) {
				clear_buffer_freed(bh);
				clear_buffer_jbddirty(bh);
				clear_buffer_mapped(bh);
				clear_buffer_new(bh);
				clear_buffer_req(bh);
				bh->b_bdev = NULL;
			}
		}

        //如果bh已经脏了，inode元数据被修改了，脏很正常吧
		if (buffer_jbddirty(bh)) {
			JBUFFER_TRACE(jh, "add to new checkpointing trans");
            //把已经备份到journal日志文件分区的jh添加到本次 commit 的transaction->t_checkpoint_list链表
			__jbd2_journal_insert_checkpoint(jh, commit_transaction);
			if (is_journal_aborted(journal))
				clear_buffer_jbddirty(bh);
		} else {
			J_ASSERT_BH(bh, !buffer_dirty(bh));
			/*
			 * The buffer on BJ_Forget list and not jbddirty means
			 * it has been freed by this transaction and hence it
			 * could not have been reallocated until this
			 * transaction has committed. *BUT* it could be
			 * reallocated once we have written all the data to
			 * disk and before we process the buffer on BJ_Forget
			 * list.
			 */
			if (!jh->b_next_transaction)
				try_to_free = 1;
		}
		JBUFFER_TRACE(jh, "refile or unfile buffer");
        //如果jh->b_next_transaction为NILL，说明jh没用则释放掉
		__jbd2_journal_refile_buffer(jh);
		jbd_unlock_bh_state(bh);
		if (try_to_free)
			release_buffer_page(bh);	/* Drops bh reference */
		else
			__brelse(bh);
		cond_resched_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);
	/*
	 * This is a bit sleazy.  We use j_list_lock to protect transition
	 * of a transaction into T_FINISHED state and calling
	 * __jbd2_journal_drop_transaction(). Otherwise we could race with
	 * other checkpointing code processing the transaction...
	 */
	write_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	/*
	 * Now recheck if some buffers did not get attached to the transaction
	 * while the lock was dropped...
	 */
	if (commit_transaction->t_forget) {
		spin_unlock(&journal->j_list_lock);
		write_unlock(&journal->j_state_lock);
		goto restart_loop;
	}

	/* Done with this transaction! */

	jbd_debug(3, "JBD2: commit phase 7\n");

	J_ASSERT(commit_transaction->t_state == T_COMMIT_JFLUSH);

	commit_transaction->t_start = jiffies;
	stats.run.rs_logging = jbd2_time_diff(stats.run.rs_logging,
					      commit_transaction->t_start);

	/*
	 * File the transaction statistics
	 */
	stats.ts_tid = commit_transaction->t_tid;
	stats.run.rs_handle_count =
		atomic_read(&commit_transaction->t_handle_count);
	trace_jbd2_run_stats(journal->j_fs_dev->bd_dev,
			     commit_transaction->t_tid, &stats.run);

	/*
	 * Calculate overall stats
	 */
	spin_lock(&journal->j_history_lock);
	journal->j_stats.ts_tid++;
	if (commit_transaction->t_requested)
		journal->j_stats.ts_requested++;
	journal->j_stats.run.rs_wait += stats.run.rs_wait;
	journal->j_stats.run.rs_request_delay += stats.run.rs_request_delay;
	journal->j_stats.run.rs_running += stats.run.rs_running;
	journal->j_stats.run.rs_locked += stats.run.rs_locked;
	journal->j_stats.run.rs_flushing += stats.run.rs_flushing;
	journal->j_stats.run.rs_logging += stats.run.rs_logging;
	journal->j_stats.run.rs_handle_count += stats.run.rs_handle_count;
	journal->j_stats.run.rs_blocks += stats.run.rs_blocks;
	journal->j_stats.run.rs_blocks_logged += stats.run.rs_blocks_logged;
	spin_unlock(&journal->j_history_lock);

	commit_transaction->t_state = T_COMMIT_CALLBACK;
	J_ASSERT(commit_transaction == journal->j_committing_transaction);
	journal->j_commit_sequence = commit_transaction->t_tid;
	journal->j_committing_transaction = NULL;
	commit_time = ktime_to_ns(ktime_sub(ktime_get(), start_time));

	/*
	 * weight the commit time higher than the average time so we don't
	 * react too strongly to vast changes in the commit time
	 */
	if (likely(journal->j_average_commit_time))
		journal->j_average_commit_time = (commit_time +
				journal->j_average_commit_time*3) / 4;
	else
		journal->j_average_commit_time = commit_time;

	write_unlock(&journal->j_state_lock);
    
	if (journal->j_checkpoint_transactions == NULL) {//如果journal->j_checkpoint_transactions没有指向的transaction
        //j_checkpoint_transactions 指向本次的commit_transaction
		journal->j_checkpoint_transactions = commit_transaction;
		commit_transaction->t_cpnext = commit_transaction;
		commit_transaction->t_cpprev = commit_transaction;
	} else {
	    //否则j_checkpoint_transactions已经有了transaction，就把本次的commit_transaction插入到checkpoint_transaction链表。
	    //这个链表上的成员都是已经commit过的transaction。为什么commit_transaction要插入到checkpoint_transaction链表呢?这是为了
	    //跟踪commit_transaction上的inode元数据对应的jh、bh，如果inode元数据已经写会ext4文件系统，这个jh就可以释放了，对应
	    //在journal日志文件分区备份inode元数据的日志描述符块就可以被释放了，就可以备份其他inode等元数据了。下边的链表插入操作
	    //是把commit_transaction插入到journal->j_checkpoint_transactions指向的transaction前边
		commit_transaction->t_cpnext =
			journal->j_checkpoint_transactions;
		commit_transaction->t_cpprev =
			commit_transaction->t_cpnext->t_cpprev;
        
		commit_transaction->t_cpnext->t_cpprev =
			commit_transaction;
		commit_transaction->t_cpprev->t_cpnext =
				commit_transaction;
	}
	spin_unlock(&journal->j_list_lock);
	/* Drop all spin_locks because commit_callback may be block.
	 * __journal_remove_checkpoint() can not destroy transaction
	 * under us because it is not marked as T_FINISHED yet */
	if (journal->j_commit_callback)
		journal->j_commit_callback(journal, commit_transaction);

	trace_jbd2_end_commit(journal, commit_transaction);
	jbd_debug(1, "JBD2: commit %d complete, head %d\n",
		  journal->j_commit_sequence, journal->j_tail_sequence);

	write_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	commit_transaction->t_state = T_FINISHED;
	/* Recheck checkpoint lists after j_list_lock was dropped */
	if (commit_transaction->t_checkpoint_list == NULL &&
	    commit_transaction->t_checkpoint_io_list == NULL) {
		__jbd2_journal_drop_transaction(journal, commit_transaction);
        //释放commit_transaction结构
		jbd2_journal_free_transaction(commit_transaction);
	}
	spin_unlock(&journal->j_list_lock);
	write_unlock(&journal->j_state_lock);
    //唤醒j_wait_done_commit等待队列上的休眠的进程
	wake_up(&journal->j_wait_done_commit);
}
