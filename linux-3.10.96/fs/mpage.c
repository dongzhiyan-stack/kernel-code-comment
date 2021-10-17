/*
 * fs/mpage.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * Contains functions related to preparing and submitting BIOs which contain
 * multiple pagecache pages.
 *
 * 15May2002	Andrew Morton
 *		Initial version
 * 27Jun2002	axboe@suse.de
 *		use bio_add_page() to build bio's just the right size
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <linux/gfp.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/prefetch.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/cleancache.h>

/*
 * I/O completion handler for multipage BIOs.
 *
 * The mpage code never puts partial pages into a BIO (except for end-of-file).
 * If a page does not map to a contiguous run of blocks then it simply falls
 * back to block_read_full_page().
 *
 * Why is this?  If a page's completion depends on a number of different BIOs
 * which can complete in any order (or at the same time) then determining the
 * status of that page is hard.  See end_buffer_async_read() for the details.
 * There is no point in duplicating all that complexity.
 */
//blk_update_request->bio_endio->mpage_end_io
static void mpage_end_io(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;

	do {
		struct page *page = bvec->bv_page;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);
		if (bio_data_dir(bio) == READ) {//读文件
			if (uptodate) {
				SetPageUptodate(page);//设置page的"PageUptodate"状态
			} else {//这个分支只有出错时才成立
				ClearPageUptodate(page);
				SetPageError(page);
			}
			unlock_page(page);
		} else { /* bio_data_dir(bio) == WRITE */ //写文件
			if (!uptodate) {
				SetPageError(page);
				if (page->mapping)
					set_bit(AS_EIO, &page->mapping->flags);
			}
			end_page_writeback(page);
		}
	} while (bvec >= bio->bi_io_vec);
	bio_put(bio);
}

static struct bio *mpage_bio_submit(int rw, struct bio *bio)
{
	bio->bi_end_io = mpage_end_io;
	submit_bio(rw, bio);
	return NULL;
}

static struct bio *
mpage_alloc(struct block_device *bdev,
		sector_t first_sector, int nr_vecs,
		gfp_t gfp_flags)
{
	struct bio *bio;

	bio = bio_alloc(gfp_flags, nr_vecs);

	if (bio == NULL && (current->flags & PF_MEMALLOC)) {
		while (!bio && (nr_vecs /= 2))
			bio = bio_alloc(gfp_flags, nr_vecs);
	}

	if (bio) {
		bio->bi_bdev = bdev;
		bio->bi_sector = first_sector;
	}
	return bio;
}

/*
 * support function for mpage_readpages.  The fs supplied get_block might
 * return an up to date buffer.  This is used to map that buffer into
 * the page, which allows readpage to avoid triggering a duplicate call
 * to get_block.
 *
 * The idea is to avoid adding buffers to pages that don't already have
 * them.  So when the buffer is up to date and the page size == block size,
 * this marks the page up to date instead of adding new buffers.
 */
static void 
map_buffer_to_page(struct page *page, struct buffer_head *bh, int page_block) 
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *page_bh, *head;
	int block = 0;

	if (!page_has_buffers(page)) {
		/*
		 * don't make any buffers if there is only one buffer on
		 * the page and the page just needs to be set up to date
		 */
		if (inode->i_blkbits == PAGE_CACHE_SHIFT && 
		    buffer_uptodate(bh)) {
			SetPageUptodate(page);    
			return;
		}
		create_empty_buffers(page, 1 << inode->i_blkbits, 0);
	}
	head = page_buffers(page);
	page_bh = head;
	do {
		if (block == page_block) {
			page_bh->b_state = bh->b_state;
			page_bh->b_bdev = bh->b_bdev;
			page_bh->b_blocknr = bh->b_blocknr;
			break;
		}
		page_bh = page_bh->b_this_page;
		block++;
	} while (page_bh != head);
}

/*
 * This is the worker routine which does all the work of mapping the disk
 * blocks and constructs largest possible bios, submits them for IO if the
 * blocks are not contiguous on the disk.
 *
 * We pass a buffer_head back and forth and use its buffer_mapped() flag to
 * represent the validity of its disk mapping and to decide when to do the next
 * get_block() call.
 */
 
/*
1 每次执行do_mpage_readpage完成一个page文件页与磁盘物理块的映射
2 遇到不连续的磁盘物理块则执行submit_bio，发送老的bio，之后新分配一个bio

mpage_readpages->do_mpage_readpage ，以实际测试为例

cat触发文件预读，文件大小64*4K，最后执行到mpage_readpages函数，循环执行64次do_mpage_readpage，每次循环读取1个文件页page。
这里举两个例子，1:这64*4k的文件数据连续的分布在磁盘地址的0~64*4K，2:这64*4K的文件数据连续的分布在磁盘地址的0~32*4k和64*4K~96*4k

mpage_readpages cat 17648 nr_pages:64
do_mpage_readpage cat 17648 nr_pages:64 page:0xffffd91e02a542c0 page->index:0 last_block_in_bio:0 first_logical_block:0 map_bh->b_blocknr:0 map_bh->b_page:          (null) map_bh->b_size:0 map_bh->b_state:0x0

开讲前，需要说明一点，测试表明ext4文件系统一个磁盘物理块大小是4K，inode->i_blkbits=12，super_block->s_blocksize_bits=12。因此，
一个文件页page只对应一个磁盘物理块


************情况1:64*4K的文件数据连续的分布在磁盘地址的0~64*4K**************************************

第1次执行do_mpage_readpage()....................................
1 第1次执行do_mpage_readpage()处理第1个page文件页的磁盘物理块，
  if (buffer_mapped(map_bh) && block_in_file > *first_logical_block...)不成立。while (page_block < blocks_per_page)成立，
  执行if (get_block(inode, block_in_file, map_bh, 0))，即ext4_get_block()，该函数的作用是
  
      根据本次读写的文件起始磁盘逻辑块号block_in_file和最大读取的文件数据量bh->b_size，完成文件磁盘逻辑地址与一片连续的磁盘物理块的
      映射。函数返回后，bh->b_blocknr是映射的磁盘物理块地址，bh->b_size是实际完成映射的磁盘物理块数量*块大小，还会设置bh->b_state
      的"mapped"状态，buffer_mapped(map_bh)则成立。
      注意，本次读取文件磁盘逻辑地址并不能一次全部完成映射。比如文件64*4K大小，但是这64*4K数据在物理磁盘分成两块，如磁盘物理地址0~32*4k和
      64*4k~96*4k。则第一次执行_ext4_get_block完成文件地址0~32*4K与磁盘物理块0~32*4k的映射，之后就知道了文件地址0~32*4K对应的磁盘物理块
      地址，执行submit_bio把文件数据传输到对应磁盘物理块(这是写，读则反过来)。接着执行_ext4_get_block完成文件地址32*4~64*4K与
      磁盘物理块64*4k~96*4k的映射，最后同样执行submit_bio把文件数据传输到对应磁盘物理块(这是写，读则反过来)。当然，如果文件64*4K数据
      在磁盘物理块是连续分布，则执行一次ext4_get_block()就能得到文件0~64*4k数据在磁盘物理块地址，后续就执行submit_bio把文件
      数据传输到对应磁盘物理块(这是写，读则反过来)

  执行ext4_get_block()后，bh->b_blocknr=4295648(文件映射的第一个磁盘物理块地址)，bh->b_size=64*4k，bh->b_state有mapped标记，
  first_logical_block始终是0，blocks_per_page始终是1，map_bh->b_size始终64*4K，nblocks=64
  block_in_file=0，page->index=0。

  在该while (page_block < blocks_per_page)里，执行里边的
  for (relative_block = 0; ; relative_block++) {}里的blocks[page_block=0] = map_bh->b_blocknr + relative_block=4295648。
  下一个for循环，else if (page_block == blocks_per_page)成立break

2  222行的if (bio && (*last_block_in_bio != blocks[0] - 1))不成立

3 执行 bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9)..)分配新的bio,并bio->bi_sector=4295648记录文件映射的第一个磁盘物理块地址

4 执行if (bio_add_page(bio, page, length, 0) < length)，为本次要传输的第1个文件页数据page分配一个bio_vec结构，记录文件数据page
  内存地址和文件页数据大小，然后把bio_vec添加到bio。

5 执行 *last_block_in_bio = blocks[blocks_per_page - 1]，其实就是*last_block_in_bio = blocks[0]=4295648,给last_block_in_bio
  赋值为该文件页映射的第一个磁盘物理块地址。
  
  ext4文件系统一个磁盘物理块4K，故一个page文件页只对应一个磁盘物理块，blocks_per_page=1.所以do_mpage_readpage()执行一次处理一个
  文件页page,只得到一个文件页page映射的磁盘物理块的地址。

6 return bio

第2次执行do_mpage_readpage()....................................
1 第2次执行 do_mpage_readpage，处理第2个page的磁盘物理块，if (buffer_mapped(map_bh) && block_in_file > *first_logical_block...)
  成立，first_logical_block始终是0，page->index是1，block_in_file是1。
  执行里边的for (relative_block = 0; ; relative_block++){}的blocks[page_block=0] =map_bh->b_blocknr+map_offset(1)+relative_block=4295648+1
  ,这是令blocks[0]记录文件映射的第二个磁盘物理块地址，然后还page_block++
  
2 while (page_block < blocks_per_page) 不成立
3 执行if (bio_add_page(bio, page, length, 0) < length)，为本次要传输的第2个文件页数据page分配一个bio_vec结构，记录文件数据page
  内存地址和文件页数据大小，然后把bio_vec添加到bio。
  
4 执行 *last_block_in_bio = blocks[blocks_per_page - 1]，其实就是*last_block_in_bio = blocks[0]=4295648+1,给last_block_in_bio
  赋值为该文件映射的第2个磁盘物理块地址
5 return bio

.....省略.......

第64次执行do_mpage_readpage()....................................
1 第64次执行 do_mpage_readpage，处理第64个page的磁盘物理块，if (buffer_mapped(map_bh) && block_in_file > *first_logical_block...)
  成立，first_logical_block始终是0，page->index是63，block_in_file是63。
  执行里边的for (relative_block = 0; ; relative_block++){}的blocks[page_block=0] =map_bh->b_blocknr+map_offset(63)+relative_block=4295648+63
  ,这是令blocks[0]记录文件映射的第64个磁盘物理块地址，然后还page_block++
  
2 while (page_block < blocks_per_page) 不成立
3 执行if (bio_add_page(bio, page, length, 0) < length)，为本次要传输的第64个文件页数据page分配一个bio_vec结构，记录文件数据page
  内存地址和文件页数据大小，然后把bio_vec添加到bio。
  
4 执行 *last_block_in_bio = blocks[blocks_per_page - 1]，其实就是*last_block_in_bio = blocks[0]=4295648+63,给last_block_in_bio
  赋值为该文件映射的第64个磁盘物理块地址

5 return bio回到mpage_readpages()，在mpage_readpages函数最后执行mpage_bio_submit(READ, bio)->submit_bio()把bio发送给磁盘驱动
6 注意，第1次到第64执行do_mpage_readpage()依次把64个page都添加到bio，这个bio始终是同一个，在mpage_bio_submit(READ, bio)发送该bio后，
  接着bio=NULL,该bio失效。之后充分分配一个bio








********情况2:64*4k的文件数据分布在物理磁盘地址0~32*4k和64*4k~96*4k 这两处*******************************************
这种情况，64*4k文件数据并不是连续分布在物理磁盘，情况发生变化

第1次执行do_mpage_readpage()....................................
1 第1次执行do_mpage_readpage()处理第1个page文件页的磁盘物理块，
  if (buffer_mapped(map_bh) && block_in_file > *first_logical_block...)不成立。while (page_block < blocks_per_page)成立，
  执行if (get_block(inode, block_in_file, map_bh, 0))，即ext4_get_block()，该函数的作用是
  
      根据本次读写的文件起始磁盘逻辑块号block_in_file和最大读取的文件数据量bh->b_size，完成文件磁盘逻辑地址与一片连续的磁盘物理块的
      映射。函数返回后，bh->b_blocknr是映射的磁盘物理块地址，bh->b_size是实际完成映射的磁盘物理块数量*块大小，还会设置bh->b_state
      的"mapped"状态，buffer_mapped(map_bh)则成立。
      注意，本次读取文件磁盘逻辑地址并不能一次全部完成映射。比如文件64*4K大小，但是这64*4K数据在物理磁盘分成两块，如磁盘物理地址0~32*4k和
      64*4k~96*4k。则第一次执行_ext4_get_block完成文件地址0~32*4K与磁盘物理块0~32*4k的映射，之后就知道了文件地址0~32*4K对应的磁盘物理块
      地址，执行submit_bio把文件数据传输到对应磁盘物理块(这是写，读则反过来)。接着执行_ext4_get_block完成文件地址32*4~64*4K与
      磁盘物理块64*4k~96*4k的映射，最后同样执行submit_bio把文件数据传输到对应磁盘物理块(这是写，读则反过来)。当然，如果文件64*4K数据
      在磁盘物理块是连续分布，则执行一次ext4_get_block()就能得到文件0~64*4k数据在磁盘物理块地址，后续就执行submit_bio把文件
      数据传输到对应磁盘物理块(这是写，读则反过来)

  -----这里就发生了变化，执行ext4_get_block()只映射了文件逻辑地址0~32*4K与物理磁盘地址0~32*4k的映射，只映射了文件前32个磁盘物理块
  
  执行ext4_get_block()后，bh->b_blocknr=4295648(文件映射的第一个磁盘物理块地址)，bh->b_size=32*4k，bh->b_state有mapped标记，
  first_logical_block是0，blocks_per_page始终是1，nblocks=32
  block_in_file=0，page->index=0。

  在该while (page_block < blocks_per_page)里，执行里边的
  for (relative_block = 0; ; relative_block++) {}里的blocks[page_block=0] = map_bh->b_blocknr + relative_block=4295648。
  下一个for循环，else if (page_block == blocks_per_page)成立break
  
2 执行 bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9)..)分配新的bio,并bio->bi_sector=4295648记录文件映射的第一个磁盘物理块地址

3 执行if (bio_add_page(bio, page, length, 0) < length)，为本次要传输的第1个文件页数据page分配一个bio_vec结构，记录文件数据page
  内存地址和文件页数据大小，然后把bio_vec添加到bio。

4 执行 *last_block_in_bio = blocks[blocks_per_page - 1]，其实就是*last_block_in_bio = blocks[0]=4295648,给last_block_in_bio
  赋值为该文件映射的第一个磁盘物理块地址。
  
  ext4文件系统一个磁盘物理块4K，故一个page文件页只对应一个磁盘物理块，blocks_per_page=1.所以do_mpage_readpage()执行一次处理一个
  文件页page,只得到一个文件页page映射的磁盘物理块的地址。
  
5 return bio

....................................


第2次执行do_mpage_readpage()....................................
1 第2次执行 do_mpage_readpage，处理第2个page的磁盘物理块，if (buffer_mapped(map_bh) && block_in_file > *first_logical_block...)
  成立，first_logical_block始终是0，page->index是1，block_in_file是1
  执行里边的for (relative_block = 0; ; relative_block++){}的blocks[page_block=0] =map_bh->b_blocknr+map_offset(1)+relative_block=4295648+1
  ,这是令blocks[0]记录文件映射的第二个磁盘物理块地址,然后还page_block++
  
2 while (page_block < blocks_per_page) 不成立
3 执行if (bio_add_page(bio, page, length, 0) < length)，为本次要传输的第2个文件页数据page分配一个bio_vec结构，记录文件数据page
  内存地址和文件页数据大小，然后把bio_vec添加到bio。
  
4 执行 *last_block_in_bio = blocks[blocks_per_page - 1]，其实就是*last_block_in_bio = blocks[0]=4295648+1,给last_block_in_bio
  赋值为该文件映射的第2个磁盘物理块地址
5 return bio

第2~32次执行do_mpage_readpage()的情况与前边一样，第33次发生变化


第33次执行do_mpage_readpage()....................................
1 第33次执行 do_mpage_readpage，处理第33个page的磁盘物理块，if (buffer_mapped(map_bh) && block_in_file > *first_logical_block...)
  成立，first_logical_block此时还是0，page->index是32，block_in_file是32，nblocks=32，page_block=0，
  map_offset =block_in_file-*first_logical_block=32，last=nblocks -map_offset=0，if (relative_block == last)成立则直接break。

  此时page_block=0，while (page_block < blocks_per_page)成立，执行if (get_block(inode, block_in_file, map_bh, 0))，即ext4_get_block()，
  完成文件逻辑地址32*4K~64*4K与物理磁盘地址64*4k~96k的映射，
  执行ext4_get_block()后，bh->b_blocknr=4295648+64，bh->b_size=32*4k，bh->b_state有mapped标记。重点来了，
  *first_logical_block = block_in_file=32，first_logical_block之后一直是32，blocks_per_page始终是1，map_bh->b_size始终32*4K，nblocks=32。

  map_bh->b_size 表示最近一次文件逻辑地址映射的连续磁盘物理块空间大小

  在该while (page_block < blocks_per_page)里，执行里边的
  for (relative_block = 0; ; relative_block++) {}里的blocks[page_block=0] = map_bh->b_blocknr + relative_block=4295648+64。
  下一个for循环，else if (page_block == blocks_per_page)成立break

2 if (bio && (*last_block_in_bio != blocks[0] - 1))成立，*last_block_in_bio=4295648+32，blocks[0] - 1 = 4295648+64-1 不成立，
  bio = mpage_bio_submit(READ, bio)把该bio发送得磁盘驱动，然后把bio=NULL.
  就是说，bio代表了一片连续的磁盘物理快，如果遇到不连续，那就要立即把bio发送给磁盘驱动。
  
2 bio为NULL，执行 bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9)..)分配新的bio,并bio->bi_sector=4295648+64
  记录文件映射的第33个磁盘物理块地址

3 执行if (bio_add_page(bio, page, length, 0) < length)，为本次要传输的第33个文件页数据page分配一个bio_vec结构，记录文件数据page
  内存地址和文件页数据大小，然后把bio_vec添加到bio。

4 执行 *last_block_in_bio = blocks[blocks_per_page - 1]，其实就是*last_block_in_bio = blocks[0]=4295648+64,给last_block_in_bio
  赋值为该文件映射的第33个磁盘物理块地址。
  
  ext4文件系统一个磁盘物理块4K，故一个page文件页只对应一个磁盘物理块，blocks_per_page=1.所以do_mpage_readpage()执行一次处理一个
  文件页page,只得到一个文件页page映射的磁盘物理块的地址。
  
5 return bio

第34次执行do_mpage_readpage()....................................
1 第34次执行 do_mpage_readpage，处理第34个page的磁盘物理块，if (buffer_mapped(map_bh) && block_in_file > *first_logical_block...)
  成立，first_logical_block是32，page->index是33，block_in_file是33
  执行里边的for (relative_block = 0; ; relative_block++){}的
  blocks[page_block=0] =map_bh->b_blocknr+map_offset(1)+relative_block=4295648+64+1，然后还page_block++
  ,这是令blocks[0]记录文件映射的第34个磁盘物理块地址
  
2 while (page_block < blocks_per_page) 不成立
3 执行if (bio_add_page(bio, page, length, 0) < length)，为本次要传输的第2个文件页数据page分配一个bio_vec结构，记录文件数据page
  内存地址和文件页数据大小，然后把bio_vec添加到bio。
  
4 执行 *last_block_in_bio = blocks[blocks_per_page - 1]，其实就是*last_block_in_bio = blocks[0]=4295648+64+1,给last_block_in_bio
  赋值为该文件映射的第34个磁盘物理块地址
5 return bio

.......34~63次一样............

第64次执行do_mpage_readpage()
1 第64次执行 do_mpage_readpage，处理第64个page的磁盘物理块，if (buffer_mapped(map_bh) && block_in_file > *first_logical_block...)
  成立，first_logical_block始终是0，page->index是63，block_in_file是63
  执行里边的for (relative_block = 0; ; relative_block++){}的
  blocks[page_block=0] =map_bh->b_blocknr+map_offset(63)+relative_block=4295648+64+31
  ,这是令blocks[0]记录文件映射的第二个磁盘物理块地址，然后还page_block++
  
2 while (page_block < blocks_per_page) 不成立
3 执行if (bio_add_page(bio, page, length, 0) < length)，为本次要传输的第64个文件页数据page分配一个bio_vec结构，记录文件数据page
  内存地址和文件页数据大小，然后把bio_vec添加到bio。
  
4 执行 *last_block_in_bio = blocks[blocks_per_page - 1]，其实就是*last_block_in_bio = blocks[0]=4295648+64+31,给last_block_in_bio
  赋值为该文件映射的第64个磁盘物理块地址

5 return bio回到mpage_readpages()，在mpage_readpages函数最后执行mpage_bio_submit(READ, bio)->submit_bio()把bio发送给磁盘驱动
6 注意，这是一次性把32个page都添加到bio，这个bio始终是同一个，在mpage_bio_submit(READ, bio)发送该bio后，
  接着bio=NULL,该bio失效。之后充分分配一个bio

ok，以上把文件逻辑地址与一片连续的磁盘物理地址构成映射、文件逻辑地址与不连续的磁盘物理地址构成映射，怎么只是把文件数据传输到磁盘或者
从磁盘读数据讲完了。

有个发现，有点微积分的概念，如果文件逻辑地址与一片连续的磁盘物理地址构成映射，调用ext4_get_block计算出
该文件映射的所有磁盘物理块地址，只分配一个bio结构，把该文件以4K文件页page为单位，用bio记录每一个文件页page地址、文件页page映射的
磁盘物理块地址。这个bio记录每一个文件页page地址、文件页page映射的磁盘物理块地址后，submit_bio，把该bio发送给磁盘驱动，把文件页page
的数据发送给对应的磁盘物理块地址。这是写，如果是读操作，则执行submit-bio从page文件页对应的磁盘物理块地址读取数据到page文件页。

如果文件逻辑地址与多片连续的磁盘物理地址构成映射，则调用ext4_get_block，计算出第一片磁盘物理块与文件逻辑地址的映射关系，知道了这片
文件逻辑地址映射的磁盘物理块地址，分配一个bio结构，记录这片文件逻辑地址每一个文件页page地址、文件页page映射的磁盘物理块地址，最后调用
submit_bio把bio发送给磁盘驱动。

然后，调用ext4_get_block，计算出第2片磁盘物理块与文件逻辑地址的映射关系，知道了这片
文件逻辑地址映射的磁盘物理块地址，再分配一个bio结构，记录这片文件逻辑地址每一个文件页page地址、文件页page映射的磁盘物理块地址，最后调用
submit_bio把bio发送给磁盘驱动
.....重复
*/
static struct bio *
do_mpage_readpage(struct bio *bio, struct page *page, unsigned nr_pages,//nr_pages:64
		sector_t *last_block_in_bio, struct buffer_head *map_bh,
		unsigned long *first_logical_block, get_block_t get_block)
{
	struct inode *inode = page->mapping->host;
	const unsigned blkbits = inode->i_blkbits;//inode->i_blkbits打印是12，我还以为是10
	
    //一个文件页page的4K内存可以保存多少个磁盘物理块的文件数据。inode->i_blkbits若为10，一个page对应4个磁盘物理块。
    //inode->i_blkbits若为12，1个page对应1个磁盘物理块
	const unsigned blocks_per_page = PAGE_CACHE_SIZE >> blkbits;
    //磁盘物理块大小，inode->i_blkbits为10时是1K，inode->i_blkbits为12时是4K
	const unsigned blocksize = 1 << blkbits;
	sector_t block_in_file;
	sector_t last_block;
	sector_t last_block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	unsigned first_hole = blocks_per_page;
	struct block_device *bdev = NULL;
	int length;
	int fully_mapped = 1;
	unsigned nblocks;
	unsigned relative_block;

	if (page_has_buffers(page))
		goto confused;
    //本次读取的page文件页对应的起始磁盘逻辑块号，不是真正的磁盘物理块地址，是个相对地址。比如page->index是0，则这里计算出的起始磁盘
    //逻辑块号是0。如果一个page对应4个磁盘物理块，这是令page页索引乘以4而计算对应起始磁盘逻辑块号
	block_in_file = (sector_t)page->index << (PAGE_CACHE_SHIFT - blkbits);
    //本轮读取的文件结束地址的磁盘逻辑块号，不是磁盘物理块号。实际测试时，执行do_mpage_readpage读取文件前64*4k地址的数据，last_block始终是64
	last_block = block_in_file + nr_pages * blocks_per_page;
    
    //文件结束地址对应的磁盘逻辑块号
	last_block_in_file = (i_size_read(inode) + blocksize - 1) >> blkbits;
	if (last_block > last_block_in_file)
		last_block = last_block_in_file;
	page_block = 0;

    /*测试时文件64*4K=256K大小，并且这64*4K数据连续的分布在物理磁盘块*/
    
	/*
	 * Map blocks using the result from the previous get_blocks call first.
	 */
	//第一次执行mpage_readpages->do_mpage_readpage，map_bh->b_size是0，但下边map_bh->b_size被赋值(last_block-block_in_file) << blkbits
	//并且还把map_bh返回给mpage_readpages，如此再执行mpage_readpages->do_mpage_readpage，map_bh不为NULL。并且第一次执行do_mpage_readpage
	//->ext4_get_block完成了map_bh映射，buffer_mapped(map_bh)返回TRUE。first_logical_block始终是0，nblocks=64，则该if成立
	nblocks = map_bh->b_size >> blkbits;//map_bh->b_size 表示文件逻辑地址与磁盘物理逻辑地址映射的空间大小
	if (buffer_mapped(map_bh) && block_in_file > *first_logical_block &&
			block_in_file < (*first_logical_block + nblocks)) {
		//测试时first_logical_block始终是0，因为64*4k文件数据连续分布在物理磁盘块，则map_offset=block_in_file
		unsigned map_offset = block_in_file - *first_logical_block;
		unsigned last = nblocks - map_offset;

        //page_block初值是0，这个for循环是把一个page页对应的所有磁盘物理块的地址记录到blocks[page_block]。如果ext4文件系统一个
        //磁盘物理块1k，则blocks_per_page=4，循环4次；如果ext4文件系统一个磁盘物理块4K，则blocks_per_page=1，循环1次
		for (relative_block = 0; ; relative_block++) {
			if (relative_block == last) {
				clear_buffer_mapped(map_bh);
				break;
			}

            //blocks_per_page是1，第1次for循环page_block是0，第2次for循环page_block是1，if成立break
			if (page_block == blocks_per_page)
				break;
            
            //测试时文件64*4k,blocks[page_block]依次保存文件0~64*4k数据映射的磁盘磁盘物理块号，一个ext4磁盘物理块4K大小
			blocks[page_block] = map_bh->b_blocknr + map_offset +
						relative_block;
			page_block++;
			block_in_file++;
		}
		bdev = map_bh->b_bdev;
	}


	/*
	 * Then do more get_blocks calls until we are done with this page.
	 */
	map_bh->b_page = page;
    //page_block表示一个page对应的第几个磁盘物理块，初值是0，每次循环加1
	while (page_block < blocks_per_page) {//测试时只有第一次成立
		map_bh->b_state = 0;
		map_bh->b_size = 0;

		if (block_in_file < last_block) {
            //本轮读取的文件大小，测试时是64*4k
			map_bh->b_size = (last_block-block_in_file) << blkbits;
            
        /*根据本次读写的文件起始磁盘逻辑块号block_in_file和最大读取的文件数据量map_bh->b_size，完成文件磁盘逻辑地址与一片连续的磁盘物理块的
            映射。函数返回后，bh->b_blocknr是映射的磁盘物理块起始地址，map_bh->b_size是实际完成映射的连续磁盘物理块数量*块大小，还会设置bh->b_state
            的"mapped"状态，buffer_mapped(map_bh)则成立。
            
       注意，本次读取文件磁盘逻辑地址并不能一次全部完成映射。比如文件64*4K大小，但是这64*4K数据在物理磁盘分成两块，如磁盘
       物理地址0~32*4k和64*4k~96*4k。则第一次执行ext4_get_block完成文件地址0~32*4K与磁盘物理记录块0~32*4k的映射，
       之后就知道了文件逻辑地址0~32*4K映射的磁盘物理记录块地址，则执行submit_bio()从这些磁盘物理记录块读取
       文件前4k*32的数据到文件逻辑地址0~4k*32映射page文件页。接着执行ext4_get_block完成文件逻辑地址32*4~64*4K与
       磁盘物理记录块64*4k~96*4k的映射，之后就知道了文件逻辑地址32*4~64*4K映射的
       磁盘物理记录块地址，则执行submit_bio()从这些磁盘物理记录块读取文件后4k*32的数据到文件逻辑地址4k*32~4k*64映射page文件页。
       当然，如果文件64*4K数据在磁盘物理记录块是连续分布，则执行一次ext4_get_block()就能得到文件0~64*4k的数据在磁盘物理记录块的地址，
       再执行submit_bio()从这些磁盘物理记录块读取文件4k*64的数据到文件逻辑地址0~4k*64映射page文件页。
       */
			if (get_block(inode, block_in_file, map_bh, 0))//ext4_get_block，成功返回0
				goto confused;
            
			*first_logical_block = block_in_file;
		}

		if (!buffer_mapped(map_bh)) {//测试时不成立
			fully_mapped = 0;
			if (first_hole == blocks_per_page)
				first_hole = page_block;
			page_block++;
			block_in_file++;
			continue;
		}

		/* some filesystems will copy data into the page during
		 * the get_block call, in which case we don't want to
		 * read it again.  map_buffer_to_page copies the data
		 * we just collected from get_block into the page's buffers
		 * so readpage doesn't have to repeat the get_block call
		 */
		if (buffer_uptodate(map_bh)) {//测试时不成立
			map_buffer_to_page(page, map_bh, page_block);
			goto confused;
		}
	
		if (first_hole != blocks_per_page)//测试时不成立
			goto confused;		/* hole -> non-hole */

		/* Contiguous blocks? */
		if (page_block && blocks[page_block-1] != map_bh->b_blocknr-1)//测试时不成立
			goto confused;
        
		nblocks = map_bh->b_size >> blkbits;//测试时文件64*4k，map_bh->b_size=64*4k，nblocks=64

        //page_block初值是0，这个for循环是把一个page页对应的所有磁盘物理块的地址记录到blocks[page_block]。如果ext4文件系统一个
        //磁盘物理块1k，则blocks_per_page=4，循环4次；如果ext4文件系统一个磁盘物理块4K，则blocks_per_page=1，循环1次
		for (relative_block = 0; ; relative_block++) {
			if (relative_block == nblocks) {
				clear_buffer_mapped(map_bh);
				break;
            //blocks_per_page是1，第1次for循环page_block是0，第2次for循环page_block是1，if成立break
			} else if (page_block == blocks_per_page)
				break;
            
            //测试时文件64*4k,blocks[page_block]依次保存文件0~64*4k数据映射的磁盘磁盘物理块号，一个ext4磁盘物理块4K大小
			blocks[page_block] = map_bh->b_blocknr + relative_block;
			page_block++;
			block_in_file++;
		}
		bdev = map_bh->b_bdev;
	}

	if (first_hole != blocks_per_page) {//测试时不成立
		zero_user_segment(page, first_hole << blkbits, PAGE_CACHE_SIZE);
		if (first_hole == 0) {
			SetPageUptodate(page);
			unlock_page(page);
			goto out;
		}
	} else if (fully_mapped) {//测试时成立
		SetPageMappedToDisk(page);
	}

	if (fully_mapped && blocks_per_page == 1 && !PageUptodate(page) &&
	    cleancache_get_page(page) == 0) {//测试时不成立
		SetPageUptodate(page);
		goto confused;
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	 
	/*这个if在遇到不连续的磁盘物理块时成立，*last_block_in_bio是上一次page文件页映射的磁盘物理块地址，blocks[0]本次page映射的磁盘
    物理块地址，如果两个地址不连续则if成立，这样就要执行mpage_bio_submit把bio的文件数据发送的磁盘物理块。紧接着就要执行mpage_alloc
    再分配一个bio。所以我们看到了，一个bio代表了文件数据逻辑地址映射的一片连续磁盘物理块，一旦遇到不连续的磁盘物理块。就要再执行
    ext4_get_block()完成 文件数据逻辑地址与下一片连续磁盘物理块的映射，这里的blocks[0]就是新映射的一片连续磁盘物理块的第一个物理块
    的地址。*/
	if (bio && (*last_block_in_bio != blocks[0] - 1))//
		bio = mpage_bio_submit(READ, bio);//里边执行submit_bio

alloc_new:
	if (bio == NULL) {
        //分配bio，bio->bi_sector则保存64*4k大小文件的第一个磁盘物理块号，以512大小为单位
		bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),//blocks[0]<<(blkbits - 9)是把磁盘物理块号变成以512为单位而已
			  	min_t(int, nr_pages, bio_get_nr_vecs(bdev)),
				GFP_KERNEL);
		if (bio == NULL)
			goto confused;
	}

    //测试时，first_hole 始终是1，first_hole << blkbits是4K
	length = first_hole << blkbits;
    //为本次要传输的文件数据page分配一个bio_vec结构，记录文件页page内存地址和文件页数据大小，然后把bio_vec添加到bio
	if (bio_add_page(bio, page, length, 0) < length) {
		bio = mpage_bio_submit(READ, bio);//里边执行submit_bio
		goto alloc_new;
	}

	relative_block = block_in_file - *first_logical_block;
    //测试时，文件64*4k大小，并且连续分布物理磁盘块，nblocks是64
	nblocks = map_bh->b_size >> blkbits;
	if ((buffer_boundary(map_bh) && relative_block == nblocks) ||
	    (first_hole != blocks_per_page))//测试时不成立
		bio = mpage_bio_submit(READ, bio);
	else//last_block_in_bio记录本次文件页page映射的最后一个磁盘物理块地址，不是文件最后的一个磁盘物理块地址。
	    //当磁盘物理块地址1K大小，page文件页映射了4个磁盘物理块地址，last_block_in_bio记录这4个磁盘物理块地址的最后一个
		*last_block_in_bio = blocks[blocks_per_page - 1];
out:
	return bio;

confused:
	if (bio)
		bio = mpage_bio_submit(READ, bio);
	if (!PageUptodate(page))
	        block_read_full_page(page, get_block);
	else
		unlock_page(page);
	goto out;
}

/**
 * mpage_readpages - populate an address space with some pages & start reads against them
 * @mapping: the address_space
 * @pages: The address of a list_head which contains the target pages.  These
 *   pages have their ->index populated and are otherwise uninitialised.
 *   The page at @pages->prev has the lowest file offset, and reads should be
 *   issued in @pages->prev to @pages->next order.
 * @nr_pages: The number of pages at *@pages
 * @get_block: The filesystem's block mapper function.
 *
 * This function walks the pages and the blocks within each page, building and
 * emitting large BIOs.
 *
 * If anything unusual happens, such as:
 *
 * - encountering a page which has buffers
 * - encountering a page which has a non-hole after a hole
 * - encountering a page with non-contiguous blocks
 *
 * then this code just gives up and calls the buffer_head-based read function.
 * It does handle a page which has holes at the end - that is a common case:
 * the end-of-file on blocksize < PAGE_CACHE_SIZE setups.
 *
 * BH_Boundary explanation:
 *
 * There is a problem.  The mpage read code assembles several pages, gets all
 * their disk mappings, and then submits them all.  That's fine, but obtaining
 * the disk mappings may require I/O.  Reads of indirect blocks, for example.
 *
 * So an mpage read of the first 16 blocks of an ext2 file will cause I/O to be
 * submitted in the following order:
 * 	12 0 1 2 3 4 5 6 7 8 9 10 11 13 14 15 16
 *
 * because the indirect block has to be read to get the mappings of blocks
 * 13,14,15,16.  Obviously, this impacts performance.
 *
 * So what we do it to allow the filesystem's get_block() function to set
 * BH_Boundary when it maps block 11.  BH_Boundary says: mapping of the block
 * after this one will require I/O against a block which is probably close to
 * this one.  So you should push what I/O you have currently accumulated.
 *
 * This all causes the disk requests to be issued in the correct order.
 */
//读取的文件页page链接在struct list_head *pages这个链表，nr_pages是读取page数。
//get_block是ext4_get_block，负责把文件逻辑地址转成该文件页数据实际保存在块设备的物理块地址
int
mpage_readpages(struct address_space *mapping, struct list_head *pages,
				unsigned nr_pages, get_block_t get_block)//get_block:ext4_get_block
{
	struct bio *bio = NULL;
	unsigned page_idx;
	sector_t last_block_in_bio = 0;
	struct buffer_head map_bh;
	unsigned long first_logical_block = 0;

	map_bh.b_state = 0;
	map_bh.b_size = 0;
    //依次取出nr_pages个page，执行submit_bio发起把page文件页对应的磁盘数据从对应磁盘物理块读取到page文件页内存
	for (page_idx = 0; page_idx < nr_pages; page_idx++) {
		struct page *page = list_entry(pages->prev, struct page, lru);

		prefetchw(&page->flags);
		list_del(&page->lru);
        
        //page按照索引index添加到radix tree，并且把page添加到LRU_INACTIVE_FILE链表
		if (!add_to_page_cache_lru(page, mapping,
					page->index, GFP_KERNEL)) {
			//第一次该循环，传入的bio是NULL，之后的循环bio不再NULL
			bio = do_mpage_readpage(bio, page,//里边执行submit_bio
					nr_pages - page_idx,
					&last_block_in_bio, &map_bh,
					&first_logical_block,
					get_block);
		}
		page_cache_release(page);
	}
	BUG_ON(!list_empty(pages));
	if (bio)
		mpage_bio_submit(READ, bio);//里边执行submit_bio
	return 0;
}
EXPORT_SYMBOL(mpage_readpages);

/*
 * This isn't called much at all
 */
int mpage_readpage(struct page *page, get_block_t get_block)
{
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;
	struct buffer_head map_bh;
	unsigned long first_logical_block = 0;

	map_bh.b_state = 0;
	map_bh.b_size = 0;
	bio = do_mpage_readpage(bio, page, 1, &last_block_in_bio,
			&map_bh, &first_logical_block, get_block);
	if (bio)
		mpage_bio_submit(READ, bio);
	return 0;
}
EXPORT_SYMBOL(mpage_readpage);

/*
 * Writing is not so simple.
 *
 * If the page has buffers then they will be used for obtaining the disk
 * mapping.  We only support pages which are fully mapped-and-dirty, with a
 * special case for pages which are unmapped at the end: end-of-file.
 *
 * If the page has no buffers (preferred) then the page is mapped here.
 *
 * If all blocks are found to be contiguous then the page can go into the
 * BIO.  Otherwise fall back to the mapping's writepage().
 * 
 * FIXME: This code wants an estimate of how many pages are still to be
 * written, so it can intelligently allocate a suitably-sized BIO.  For now,
 * just allocate full-size (16-page) BIOs.
 */

struct mpage_data {
	struct bio *bio;
	sector_t last_block_in_bio;
	get_block_t *get_block;
	unsigned use_writepage;
};

static int __mpage_writepage(struct page *page, struct writeback_control *wbc,
		      void *data)
{
	struct mpage_data *mpd = data;
	struct bio *bio = mpd->bio;
	struct address_space *mapping = page->mapping;
	struct inode *inode = page->mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	unsigned long end_index;
	const unsigned blocks_per_page = PAGE_CACHE_SIZE >> blkbits;
	sector_t last_block;
	sector_t block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	unsigned first_unmapped = blocks_per_page;
	struct block_device *bdev = NULL;
	int boundary = 0;
	sector_t boundary_block = 0;
	struct block_device *boundary_bdev = NULL;
	int length;
	struct buffer_head map_bh;
	loff_t i_size = i_size_read(inode);
	int ret = 0;

	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;

		/* If they're all mapped and dirty, do it */
		page_block = 0;
		do {
			BUG_ON(buffer_locked(bh));
			if (!buffer_mapped(bh)) {
				/*
				 * unmapped dirty buffers are created by
				 * __set_page_dirty_buffers -> mmapped data
				 */
				if (buffer_dirty(bh))
					goto confused;
				if (first_unmapped == blocks_per_page)
					first_unmapped = page_block;
				continue;
			}

			if (first_unmapped != blocks_per_page)
				goto confused;	/* hole -> non-hole */

			if (!buffer_dirty(bh) || !buffer_uptodate(bh))
				goto confused;
			if (page_block) {
				if (bh->b_blocknr != blocks[page_block-1] + 1)
					goto confused;
			}
			blocks[page_block++] = bh->b_blocknr;
			boundary = buffer_boundary(bh);
			if (boundary) {
				boundary_block = bh->b_blocknr;
				boundary_bdev = bh->b_bdev;
			}
			bdev = bh->b_bdev;
		} while ((bh = bh->b_this_page) != head);

		if (first_unmapped)
			goto page_is_mapped;

		/*
		 * Page has buffers, but they are all unmapped. The page was
		 * created by pagein or read over a hole which was handled by
		 * block_read_full_page().  If this address_space is also
		 * using mpage_readpages then this can rarely happen.
		 */
		goto confused;
	}

	/*
	 * The page has no buffers: map it to disk
	 */
	BUG_ON(!PageUptodate(page));
	block_in_file = (sector_t)page->index << (PAGE_CACHE_SHIFT - blkbits);
	last_block = (i_size - 1) >> blkbits;
	map_bh.b_page = page;
	for (page_block = 0; page_block < blocks_per_page; ) {

		map_bh.b_state = 0;
		map_bh.b_size = 1 << blkbits;
		if (mpd->get_block(inode, block_in_file, &map_bh, 1))
			goto confused;
		if (buffer_new(&map_bh))
			unmap_underlying_metadata(map_bh.b_bdev,
						map_bh.b_blocknr);
		if (buffer_boundary(&map_bh)) {
			boundary_block = map_bh.b_blocknr;
			boundary_bdev = map_bh.b_bdev;
		}
		if (page_block) {
			if (map_bh.b_blocknr != blocks[page_block-1] + 1)
				goto confused;
		}
		blocks[page_block++] = map_bh.b_blocknr;
		boundary = buffer_boundary(&map_bh);
		bdev = map_bh.b_bdev;
		if (block_in_file == last_block)
			break;
		block_in_file++;
	}
	BUG_ON(page_block == 0);

	first_unmapped = page_block;

page_is_mapped:
	end_index = i_size >> PAGE_CACHE_SHIFT;
	if (page->index >= end_index) {
		/*
		 * The page straddles i_size.  It must be zeroed out on each
		 * and every writepage invocation because it may be mmapped.
		 * "A file is mapped in multiples of the page size.  For a file
		 * that is not a multiple of the page size, the remaining memory
		 * is zeroed when mapped, and writes to that region are not
		 * written out to the file."
		 */
		unsigned offset = i_size & (PAGE_CACHE_SIZE - 1);

		if (page->index > end_index || !offset)
			goto confused;
		zero_user_segment(page, offset, PAGE_CACHE_SIZE);
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	if (bio && mpd->last_block_in_bio != blocks[0] - 1)
		bio = mpage_bio_submit(WRITE, bio);

alloc_new:
	if (bio == NULL) {
		bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),
				bio_get_nr_vecs(bdev), GFP_NOFS|__GFP_HIGH);
		if (bio == NULL)
			goto confused;
	}

	/*
	 * Must try to add the page before marking the buffer clean or
	 * the confused fail path above (OOM) will be very confused when
	 * it finds all bh marked clean (i.e. it will not write anything)
	 */
	length = first_unmapped << blkbits;
	if (bio_add_page(bio, page, length, 0) < length) {
		bio = mpage_bio_submit(WRITE, bio);
		goto alloc_new;
	}

	/*
	 * OK, we have our BIO, so we can now mark the buffers clean.  Make
	 * sure to only clean buffers which we know we'll be writing.
	 */
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;
		unsigned buffer_counter = 0;

		do {
			if (buffer_counter++ == first_unmapped)
				break;
			clear_buffer_dirty(bh);
			bh = bh->b_this_page;
		} while (bh != head);

		/*
		 * we cannot drop the bh if the page is not uptodate
		 * or a concurrent readpage would fail to serialize with the bh
		 * and it would read from disk before we reach the platter.
		 */
		if (buffer_heads_over_limit && PageUptodate(page))
			try_to_free_buffers(page);
	}

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);
	if (boundary || (first_unmapped != blocks_per_page)) {
		bio = mpage_bio_submit(WRITE, bio);
		if (boundary_block) {
			write_boundary_block(boundary_bdev,
					boundary_block, 1 << blkbits);
		}
	} else {
		mpd->last_block_in_bio = blocks[blocks_per_page - 1];
	}
	goto out;

confused:
	if (bio)
		bio = mpage_bio_submit(WRITE, bio);

	if (mpd->use_writepage) {
		ret = mapping->a_ops->writepage(page, wbc);
	} else {
		ret = -EAGAIN;
		goto out;
	}
	/*
	 * The caller has a ref on the inode, so *mapping is stable
	 */
	mapping_set_error(mapping, ret);
out:
	mpd->bio = bio;
	return ret;
}

/**
 * mpage_writepages - walk the list of dirty pages of the given address space & writepage() all of them
 * @mapping: address space structure to write
 * @wbc: subtract the number of written pages from *@wbc->nr_to_write
 * @get_block: the filesystem's block mapper function.
 *             If this is NULL then use a_ops->writepage.  Otherwise, go
 *             direct-to-BIO.
 *
 * This is a library function, which implements the writepages()
 * address_space_operation.
 *
 * If a page is already under I/O, generic_writepages() skips it, even
 * if it's dirty.  This is desirable behaviour for memory-cleaning writeback,
 * but it is INCORRECT for data-integrity system calls such as fsync().  fsync()
 * and msync() need to guarantee that all the data which was dirty at the time
 * the call was made get new I/O started against them.  If wbc->sync_mode is
 * WB_SYNC_ALL then we were called for data integrity and we must wait for
 * existing IO to complete.
 */
int
mpage_writepages(struct address_space *mapping,
		struct writeback_control *wbc, get_block_t get_block)
{
	struct blk_plug plug;
	int ret;

	blk_start_plug(&plug);

	if (!get_block)
		ret = generic_writepages(mapping, wbc);
	else {
		struct mpage_data mpd = {
			.bio = NULL,
			.last_block_in_bio = 0,
			.get_block = get_block,
			.use_writepage = 1,
		};

		ret = write_cache_pages(mapping, wbc, __mpage_writepage, &mpd);
		if (mpd.bio)
			mpage_bio_submit(WRITE, mpd.bio);
	}
	blk_finish_plug(&plug);
	return ret;
}
EXPORT_SYMBOL(mpage_writepages);

int mpage_writepage(struct page *page, get_block_t get_block,
	struct writeback_control *wbc)
{
	struct mpage_data mpd = {
		.bio = NULL,
		.last_block_in_bio = 0,
		.get_block = get_block,
		.use_writepage = 0,
	};
	int ret = __mpage_writepage(page, wbc, &mpd);
	if (mpd.bio)
		mpage_bio_submit(WRITE, mpd.bio);
	return ret;
}
EXPORT_SYMBOL(mpage_writepage);
