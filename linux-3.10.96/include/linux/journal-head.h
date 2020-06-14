/*
 * include/linux/journal-head.h
 *
 * buffer_head fields for JBD
 *
 * 27 May 2001 Andrew Morton
 *	Created - pulled out of fs.h
 */

#ifndef JOURNAL_HEAD_H_INCLUDED
#define JOURNAL_HEAD_H_INCLUDED

typedef unsigned int		tid_t;		/* Unique transaction ID */
typedef struct transaction_s	transaction_t;	/* Compound transaction type */


struct buffer_head;

struct journal_head {
	/*
	 * Points back to our buffer_head. [jbd_lock_bh_journal_head()]
	 */
	struct buffer_head *b_bh;//指向bh,jbd2_journal_add_journal_head()

	/*
	 * Reference count - see description in journal.c
	 * [jbd_lock_bh_journal_head()]
	 */
	int b_jcount;//bh与jh构成联系后，加1

	/*
	 * Journalling list for this buffer [jbd_lock_bh_state()]
	 * NOTE: We *cannot* combine this with b_modified into a bitfield
	 * as gcc would then (which the C standard allows but which is
	 * very unuseful) make 64-bit accesses to the bitfield and clobber
	 * b_jcount if its update races with bitfield modification.
	 */
	//代表jh在tranction哪个链表上，常见的有BJ_Metadata、BJ_Forget、BJ_IO、BJ_Shadow、BJ_LogCtl、BJ_Reserved
	unsigned b_jlist;

	/*
	 * This flag signals the buffer has been modified by
	 * the currently running transaction
	 * [jbd_lock_bh_state()]
	 */
	//为1应该是jh对应的bh被修改了
	unsigned b_modified;

	/*
	 * Copy of the buffer data frozen for writing to the log.
	 * [jbd_lock_bh_state()]
	 */
	//网上说这是，jbd遇到转义，将bh的数据先保存在这里，写入log时用到。jbd2_journal_get_write_access()中指向分配的frozen_data
	char *b_frozen_data;

	/*
	 * Pointer to a saved copy of the buffer containing no uncommitted
	 * deallocation references, so that allocations can avoid overwriting
	 * uncommitted deletes. [jbd_lock_bh_state()]
	 */
	char *b_committed_data;

	/*
	 * Pointer to the compound transaction which owns this buffer's
	 * metadata: either the running transaction or the committing
	 * transaction (if there is one).  Only applies to buffers on a
	 * transaction's data or metadata journaling list.
	 * [j_list_lock] [jbd_lock_bh_state()]
	 * Either of these locks is enough for reading, both are needed for
	 * changes.
	 */
	//do_get_write_access->__jbd2_journal_file_buffer,指向当前正在运行的transaction
	transaction_t *b_transaction;

	/*
	 * Pointer to the running compound transaction which is currently
	 * modifying the buffer's metadata, if there was already a transaction
	 * committing it when the new transaction touched it.
	 * [t_list_lock] [jbd_lock_bh_state()]
	 */
	//do_get_write_access(),jh->b_next_transaction指向当前正运行的transaction，
	//jh原来在的jh处理完这个jh后，接着轮到正在运行的transaction处理这个jh.
	//jbd2_journal_refile_buffer->__jbd2_journal_refile_buffer()取出b_next_transaction指向的transaction，把jh添加到这个transaction的链表
	transaction_t *b_next_transaction;

	/*
	 * Doubly-linked list of buffers on a transaction's data, metadata or
	 * forget queue. [t_list_lock] [jbd_lock_bh_state()]
	 */
	 //__jbd2_journal_file_buffer->__blist_add_buffer，把jh添加到transaction的list链表时，这个list链表也是一个struct journal_head结构
	//要传输的jh的b_tprev和b_tnext分别指向transation list链表struct journal_head结构的成员
	//transation list链表的b_tnext和b_tprev指向要传输的jh的struct journal_head结构，什么破乱七八糟的关系
	struct journal_head *b_tnext, *b_tprev;

	/*
	 * Pointer to the compound transaction against which this buffer
	 * is checkpointed.  Only dirty buffers can be checkpointed.
	 * [j_list_lock]
	 */
	transaction_t *b_cp_transaction;

	/*
	 * Doubly-linked list of buffers still remaining to be flushed
	 * before an old transaction can be checkpointed.
	 * [j_list_lock]
	 */
	struct journal_head *b_cpnext, *b_cpprev;

	/* Trigger type */
	struct jbd2_buffer_trigger_type *b_triggers;

	/* Trigger type for the committing transaction's frozen data */
	struct jbd2_buffer_trigger_type *b_frozen_triggers;
};

#endif		/* JOURNAL_HEAD_H_INCLUDED */
