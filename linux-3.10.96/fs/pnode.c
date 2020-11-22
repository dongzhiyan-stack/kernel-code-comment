/*
 *  linux/fs/pnode.c
 *
 * (C) Copyright IBM Corporation 2005.
 *	Released under GPL v2.
 *	Author : Ram Pai (linuxram@us.ibm.com)
 *
 */
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include "internal.h"
#include "pnode.h"

/* return the next shared peer mount of @p */
static inline struct mount *next_peer(struct mount *p)//返回peer group同一个mount组中的下一个mount
{
	return list_entry(p->mnt_share.next, struct mount, mnt_share);
}

static inline struct mount *first_slave(struct mount *p)
{//这是从mnt_slave_list链表取出子slave，不是同一个slave mount组的mount
	return list_entry(p->mnt_slave_list.next, struct mount, mnt_slave);
}

static inline struct mount *next_slave(struct mount *p)//返回同是slave属性mount组的下一个mount
{
	return list_entry(p->mnt_slave.next, struct mount, mnt_slave);
}

static struct mount *get_peer_under_root(struct mount *mnt,
					 struct mnt_namespace *ns,
					 const struct path *root)
{
	struct mount *m = mnt;

	do {
		/* Check the namespace first for optimization */
		if (m->mnt_ns == ns && is_path_reachable(m, m->mnt.mnt_root, root))
			return m;

		m = next_peer(m);
	} while (m != mnt);

	return NULL;
}

/*
 * Get ID of closest dominating peer group having a representative
 * under the given root.
 *
 * Caller must hold namespace_sem
 */
int get_dominating_id(struct mount *mnt, const struct path *root)
{
	struct mount *m;

	for (m = mnt->mnt_master; m != NULL; m = m->mnt_master) {
		struct mount *d = get_peer_under_root(m, mnt->mnt_ns, root);
		if (d)
			return d->mnt_group_id;
	}

	return 0;
}

static int do_make_slave(struct mount *mnt)
{
	struct mount *peer_mnt = mnt, *master = mnt->mnt_master;
	struct mount *slave_mnt;

	/*
	 * slave 'mnt' to a peer mount that has the
	 * same root dentry. If none is available then
	 * slave it to anything that is available.
	 */
	while ((peer_mnt = next_peer(peer_mnt)) != mnt &&
	       peer_mnt->mnt.mnt_root != mnt->mnt.mnt_root) ;

	if (peer_mnt == mnt) {
		peer_mnt = next_peer(mnt);
		if (peer_mnt == mnt)
			peer_mnt = NULL;
	}
	if (mnt->mnt_group_id && IS_MNT_SHARED(mnt) &&
	    list_empty(&mnt->mnt_share))
		mnt_release_group_id(mnt);

	list_del_init(&mnt->mnt_share);
	mnt->mnt_group_id = 0;

	if (peer_mnt)
		master = peer_mnt;

	if (master) {
		list_for_each_entry(slave_mnt, &mnt->mnt_slave_list, mnt_slave)
			slave_mnt->mnt_master = master;
		list_move(&mnt->mnt_slave, &master->mnt_slave_list);
		list_splice(&mnt->mnt_slave_list, master->mnt_slave_list.prev);
		INIT_LIST_HEAD(&mnt->mnt_slave_list);
	} else {
		struct list_head *p = &mnt->mnt_slave_list;
		while (!list_empty(p)) {
                        slave_mnt = list_first_entry(p,
					struct mount, mnt_slave);
			list_del_init(&slave_mnt->mnt_slave);
			slave_mnt->mnt_master = NULL;
		}
	}
	mnt->mnt_master = master;
	CLEAR_MNT_SHARED(mnt);
	return 0;
}

/*
 * vfsmount lock must be held for write
 */
void change_mnt_propagation(struct mount *mnt, int type)
{
	if (type == MS_SHARED) {
		set_mnt_shared(mnt);
		return;
	}
	do_make_slave(mnt);
	if (type != MS_SLAVE) {
		list_del_init(&mnt->mnt_slave);
		mnt->mnt_master = NULL;
		if (type == MS_UNBINDABLE)
			mnt->mnt.mnt_flags |= MNT_UNBINDABLE;
		else
			mnt->mnt.mnt_flags &= ~MNT_UNBINDABLE;
	}
}

/*
 * get the next mount in the propagation tree.
 * @m: the mount seen last
 * @origin: the original mount from where the tree walk initiated
 *
 * Note that peer groups form contiguous segments of slave lists.
 * We rely on that in get_source() to be able to find out if
 * vfsmount found while iterating with propagation_next() is
 * a peer of one we'd found earlier.
 */
/*
  mount1是dest mount，自身属于share mount组。mount1_1和mount1_2和mount_1_3属于一个slave mount组，他们的mnt_master都指向mount1,
  下边没有画全,正常slave mount组的mount->mnt_master都指向其克隆母体。
  
  假设本次操作是 mount --bind /home/test  /home/
  
  mount1---mount2---mount3---mount4---mount5 (share/peer mount组1)
     |       |
     |       |
     |       mount2_1---mount2_2---mount2_3---mount2_4---mount2_5  (slave mount组1)
     |                                                      
    mount1_1---mount1_2---mount_1_3  (slave mount组2)      
                  |
                  mount1_2_1---mount1_2_2---mount1_2_3 (slave mount组3)
                  
   下边以mount1这个dest mount为例，非常详细介绍传播过程，举了个例子一目了然，没有最强大脑超强的空间力，却自欺欺人只想靠想解决问题，悲哀
   
step 1:mount1是slave mount克隆母体，第一个执行propagation_next()，直接return first_slave(m)返回子slave mount，mount_1_1

step 2:m是mount_1_1，m->mnt_master是mount_1，origin->mnt_master即mount1->mnt_master是NULL，if (master == origin->mnt_master)不成立，
  else if (m->mnt_slave.next != &master->mnt_slave_list)成立，这个判断的意思是m是否这个slave mount组的最后一个mount，即mount_1_3，
  master->mnt_slave_list即mount_1->mnt_slave_list链表上的保存的是slave mount组的第一个mount，如果m是slave mount组的最后一个mount，
  则m->mnt_slave.next也是slave mount组的第一个mount，如果m->mnt_slave.next == &master->mnt_slave_list，说明这个slave mount组的所有mount
  都遍历完了。m是mount_1_1时，执行return next_slave(m)返回mount_1_2。
  
step 3:下次执行propagation_next()，m是mount_1_2，mount_1_2是slave mount克隆母体，则执行return first_slave(m)返回其子slave mount，
  即mount1_2_1。
  
step 4:下次执行propagation_next()，m是mount1_2_1,m->mnt_master是mount1_2，if (master == origin->mnt_master)肯定不成立，下边的
  else if (m->mnt_slave.next != &master->mnt_slave_list)成立。执行return next_slave(m)返回mount1_2_2。下次执行propagation_next()，
  执行return next_slave(m)返回mount1_2_3。下次执行propagation_next()，m是mount1_2_3，mount1_2_3是slave mount组3的最后一个mount，
  m->mnt_slave.next和&master->mnt_slave_list都slave mount组3的第一个mount，那个else if不成立。该mount组遍历完了，则执行m = master，
  m变为slave mount组3的母体mount_1_2。此时相当于返回了slave mount组2，接着遍历slave mount组2的mount，执行return next_slave(m)
  返回mount_1_3
  
step 5:下次执行propagation_next()，m是mount_1_3，mount_1_3是slave mount组2的最后一个mount，m->mnt_slave.next和&master->mnt_slave_list
  都slave mount组2的第一个mount，那个else if不成立。该mount组遍历完了，则执行m = master，m变为slave mount组2的母体mount_1。
  此时相当于返回了"share/peer mount组1"。m->mnt_master即mount_1->mnt_master是NULL，origin->mnt_master也是mount_1->mnt_master，
  if (master == origin->mnt_master)成立，则执行next_peer(m)，返回mount2。
  
step 6:下次执行propagation_next()，m是mount_2，mount_2是slave mount组1的母体，此时就要按照step2~step4，一个个遍历slave mount组1的
  mount2_1~mount2_5并返回，这个过程不再说了，看step2~step4。等再次propagation_next()，m是mount2_5，是slave mount组1的最后一个mount，
  直接执行m = master，m变为slave mount组1母体mount_2，接着回到while(1)循环开头，mount_2->mnt_master是NULL，
  if (master == origin->mnt_master)成立，执行next_peer(m)并返回mount_3。

step 7:下次执行propagation_next()，m是mount_3，mount_3->mnt_master是NULL，if (master == origin->mnt_master)成立，执行next_peer(m)
  并返回mount_4。下次执行propagation_next()，m是mount_4，mount_4->mnt_master是NULL，if (master == origin->mnt_master)成立，
  执行next_peer(m)并返回mount_5。下次执行propagation_next()，m是mount_5，mount_5->mnt_master是NULL，if (master == origin->mnt_master)
  成立，但是很可惜，此时next=next_peer(m)返回链表头mount1，(next == origin)成立，propagation_next()终于返回NULL。如此，以本次dest mount
  即mount1的传播遍历，宣告结束。propagation_next()代码牛逼呀，短短10行代码，就把这么负责的mount关系遍历完了!!!!!

step 8:有没有可能dest mount是mount1_1，这样，dest mount本身就是一个slave mount组的mount成员?我认为没有可能，因为一个实际的mount，
  是必然要执行mount /dev/sda3 /home/挂载到某个目录形成的，一个挂载点目录代表的挂载源文件系统mount，一定是有实际文件系统对应的，这种
  mount与传播形成的slave mount或者share mount或者private mount不一样。所以dest mount代表的挂载点目录所在文件系统的mount，应该是默认的
  属性，即share属性，但它不是克隆生成的。mount --make-slave /dev/sdb  /mnt/test2/ 竟然也可以。但是考虑到一般都是
  mount --bind 时才会指定 --make-slave/--make-private/--make-share属性。现在就暂时认定，dest mount不会有privae属性，它不是slave mount组的。

 总结，现在对mount的传播遍历规则一斤搞清楚了:以dest mount为源头，遍历遍历shared mount或者slave mount组的mount。正常情况，dest mount
 是在share mount组，所以遍历这个share mount组的一个个成员并返回。但是，这个share mount的mount可能是slave mount组的母体。这种情况，就
 进入这个slave mount组遍历slave mount并返回，遍历完则返回slave mount母体，继续遍历母体所在的那个mount组。注意，slave mount组的mount
 也可能是另一个slave mount组的母体，这种就继续深入这一层的slave mount遍历mount，遍历完全部的slave mount再返回母体mount那一层。如果没有
 slave mount，遍历过程非常简单，一个个遍历share mount组的mount就行了。如果中途碰到有个mount是slave mount组的母体，那就遍历这个
 slave mount组的mount，遍历完返回母体那一层的mount继续遍历。
*/
//返回peer group即同是shared属性mount组中的下一个mount或者同是slave属性mount组的下一个mount。貌似所有父子mount结构有shared属性的mount
//都靠其mnt_share成员构成一个单向链表。所有父子mount结构有slave属性的mount靠其mnt_slave成员构成一个单向链表。propagation_next()函数
//貌似就是以本次mount命令的dest mount结构为开始，通过mount结构的mnt_share和mnt_slave成员，遍历所有同一个属性组所有的mount结构
static struct mount *propagation_next(struct mount *m,/*m是share mount组或者slave mount组里的mount，初值是dest mount*/
					 struct mount *origin)/*origin 永远是本次的dest mount*/
{
	// are there any slaves of this mount? 
    /*m不是新mount，并且m是slave mount克隆母体，则返回它的子slave mount。m是克隆母体，m->mnt_slave_list挂的就是子slave mount，非NULL，
      list_empty()返回false，if成立。mount操作带slave属性时，克隆soure mount 生成的新mount，新mount添加到母体mount的mnt_slave_list链表。
      如果m->mnt_slave_list为NULL，则说明m就没有子slave mount，子slave mount!*/
    if (!IS_MNT_NEW(m) && !list_empty(&m->mnt_slave_list))
        //如果m有子slave mount,从m->mnt_slave_list链表取出其子slave，不是同一个slave mount组的mount
		return first_slave(m);
    
    /*一个mount不会既有slave属性也有share属性，share属性的mount肯定靠其mnt_share添加到同share mount组的mount的mnt_share链表。
    有slave属性的mount靠其mnt_slave添加到同slave mount组的mount的mnt_slave链表，或者是克隆母体mount的mnt_slave_list链表。存在这样一种
    mount，它是mount shared组的mount，但是它又是某个slave mount组mount的克隆母体。如果m是这种shared，则先上边的执行first_slave(m)返回
    这slave mount组的第一个mount，等下次循环执行该函数，就会执行下边的mount，*/
	while (1) {
        //master即m的克隆母体mount，如果m没有slave属性，m->mnt_master是NULL。share和private属性的mount结构mnt_master就是NULL
		struct mount *master = m->mnt_master;

        /*origin->mnt_master永远是dest mount的mnt_master，如果dest mount没有private属性，origin->mnt_master永远是NULL。master是每次遍历
         的同一个slave或shared mount组的m的master，m的初值就是dest mount。如果dest mount是一个share mount组的一个mount，那第一次判断
         origin->mnt_master和master都是NULL，成立，return share mount组的next mount。下次执行该函数。m就是那个next mount，m->mnt_master
         还是NULL，if (master == origin->mnt_master)还成立，接着返回shared mount组的next next mount。直到遍历完，(next == origin)则返回NULL。
         */
        //如果m是share mount组的成员，则next_peer(m)返回share mount组的下一个mount，直到遍历完share mount组的的所有mount，返回NULL
        //origin即dest mount现在暂时认定不会是slave mount成员，一定是默认的share属性，看上边的step 8分析。
		if (master == origin->mnt_master) {
			struct mount *next = next_peer(m);
			return (next == origin) ? NULL : next;
      //到这里，m是一定是slave mount组的成员，则next_slave(m)一直遍历返回slave mount组的mount，直到遍历完，if不成立。则执行下边的m = master;
		} else if (m->mnt_slave.next != &master->mnt_slave_list)
			return next_slave(m);

		// back at master 
		//只有m是slave mount组的最后一个mount，mount都遍历完了，才会执行这里的m = master，则m变成了slave mount组的母体mount，
		//相当于返回母体mount所在的那一层mount，继续循环遍历。
		m = master;
	}
}

/*
 * return the source mount to be used for cloning
 *
 * @dest 	the current destination mount
 * @last_dest  	the last seen destination mount
 * @last_src  	the last seen source mount
 * @type	return CL_SLAVE if the new mount has to be
 * 		cloned as a slave.
 */
/*
propagate_mnt->propagation_next()得到slave mount组或者share mount组的一个mount
             ->get_source()，得到一个克隆母体的mount
             ->copy_tree()，根据上边的克隆母体mount克隆一个mount
假设本次操作时 mount --bind /home/test  /home/,mount1是dest mount

mount1---mount2---mount3---mount4---mount5 (share/peer mount组1)
   |       
   |                                                             
  mount1_1---mount1_2  (slave mount组2)      
                
1 mount1是dest mount，第一次循环，propagation_next()返回mount_1_1。get_source(),dest就是mount_1_1，last_dest是本次原始dest mount即mount1，
  last_src是本次mount的原始source mount，while (last_dest != dest->mnt_master)和if (p_last_dest)都不成立，则*type = CL_SLAVE即赋予
  将来克隆的mount为slave属性，return last_src即返回本次挂载的原始source mount。然后copy_tree()就以last_src为克隆母体，
  生成mount结构child_1_1，这个mount的属性是slave，child_1_1->mnt_master是原始source mount。再last_dest=mount_1_1，last_src=child_1_1，
  这段操作在propagate_mnt()函数最后执行，last_dest被赋值为本次propagation_next()返回的m，last_src被赋值为每次克隆生成的child。
  
2 第二次循环，propagation_next()返回mount_1_2。get_source(),则dest就是mount_1_2，last_dest是mount_1_1，last_src是child_1_1，
  while (last_dest != dest->mnt_master)成立，则last_dest = last_dest->mnt_master后，last_dest变成mount1,last_src = last_src->mnt_master
  后，last_src变成本次挂载的原始source mount，接着退出while，if (p_last_dest)成立但是没用，*type = CL_SLAVE，last_src此时还是本次挂载
  的原始source mount。故get_source()还是返回本次挂载的原始source mount。之后执行的copy_tree()还是照着原始source mount克隆mount，
  克隆生成了child_1_2，这个mount的属性是slave，child_1_2->mnt_master是原始source mount。
  接着执行propagate_mnt()后边的代码，last_dest=mount_1_2(即m)，last_src=child_1_2(即child)

3 第三次循环，propagation_next()返回mount2,这是mount share组的mount。此时执行get_source(),dest是mount2,last_src是child_1_2，
  last_dest是mount_1_2。dest->mnt_master是NULL，while成立，则p_last_dest = last_dest，p_last_dest变成mount_1_2，p_last_src = last_src，
  p_last_src变成child_1_2，last_dest = last_dest->mnt_master后last_dest变成mount1，last_src = last_src->mnt_master，last_src变成
  原始source mount，while依然成立。继续执行while里的4个赋值，p_last_dest变成mount1,p_last_src变成原始source mount，last_dest变成NULL，
  last_src变成NULL，while不成立。if (p_last_dest)成立，p_last_dest = next_peer(p_last_dest)后，p_last_dest变成mount2，
  则if (dest == p_last_dest)成立，*type = CL_MAKE_SHARED，返回的mount是p_last_src即原始source mount。之后执行的copy_tree()还是照着
  原始source mount克隆mount，克隆生成了child_2，这个mount的属性是share，跟克隆母体source mount属于同一个share mount组。
  接着执行propagate_mnt()后边的代码，last_dest=mount_2(即m)，last_src=child_2(即child)
  
4 第4次循环，propagation_next()返回mount3，此时执行get_source(),dest是mount3，last_src是child_2，last_dest=mount_2。while成立，
  执行while里的4个赋值，p_last_dest变成mount_2，p_last_src变成child_2，last_dest变成NULL，last_src变成NULL，都是share mount，则其
  mnt_master都是NULL。if (p_last_dest)成立，p_last_dest = next_peer(p_last_dest)返回mount_3,if (dest == p_last_dest)成立，
  则*type = CL_MAKE_SHARED，返回p_last_src即last_src即child_2。然后执行copy_tree()照着last_src即child_2克隆mount，克隆生成了child_3，
  这个mount的属性是share，跟克隆母体child_2属于同一个share mount组，则跟原始source mount也是一个share mount组。
  接着执行propagate_mnt()后边的代码，last_dest=mount_3(即m)，last_src=child_3(即child)
  
5 第5次循环和第6次循环，跟第三次循环原理就一样了，每次get_source()时，last_src都是上一步克隆生成的child，然后返回这个child，作为克隆母体
  ，克隆生成新的child:copy_tree()中以child_3克隆生成child_4(mount4对应的);copy_tree()以child_4克隆生成child_5(mount5对应的)。

总结:get_source()得到dest 这个mount对应的source mount。规则是，如果是dest是slave mount，则get_source()返回的永远是最近一步的last_src
那个mount，相当于dest为slave则get_source()返回的克隆母体永远是last_src，这个last_src就是这个slave mount组克隆母体对应的那个source mount
吧。是的，mount1的slave mount组成员mount1_1和mount1_2是dest时，get_source返回的就是本次挂载的原始source mount，而这个原始souce mount和
mount1就是本次mount bind的源mount和目的mount。如果dest 是share组mount成员，get_source()返回的last_src，永远是
propagate_mnt->child = copy_tree(source..) 这个克隆生成child(第一次除外，last_src是本次原始dest mount的source mount)，实时在变。

1  get_source()dest是slave mount组成员，返回的永远是这个slave mount组2的克隆母体(即mount1)对应的source mount，last_src是这个source mount
   不变。然后每一次propagate_mnt()中都是执行copy_tree()，以这个source mount克隆生成新的mount即child，child->mnt_master为source mount。
   while (last_dest != dest->mnt_master)这个循环，就是要一直向上遍历last_dest->mnt_master，last_src=last_src->mnt_master也跟着向上遍历，
   直到last_dest是dest的mnt_master(即mount1),此时last_src也变成了跟mount1对应的source mount。什么意思呢，mount1作为本次的dest mount，
   肯定有一个source mount与之对应，本案例就是本次挂载形成的source mount。
   
2  get_source()dest是share mount组成员，除了第一次是返回本次mount挂载的source mount，然后照着克隆生成新的mount即child，child和克隆母体 
   是同一个mount共享组。然后last_src=child。之后的几次循环，get_source()都是返回上次克隆生成child，然后以此为母体再克隆。所有克隆生成
   child都和本次mount挂载的source mount是一个mount共享组。share mount组mount的遍历，每次get_source()返回的都是上一个slave mount组的
   对应的mount成员克隆生成child。当dest 是mount2时，get_source()返回本次挂载原始source mount，然后执行copy_tree()以这个souce mount为克隆
   母体克隆生成child_2，接着执行mnt_set_mountpoint(mount2,dest_mp,child_2)，设置child_2和mount2构成父子关系，即child2->mnt_parent=mount2,
   child2就是mount2的source mount，mount2是dest mount，一一对应。child_2的挂载点目录是dest_mp->dentry，
   即本次mount bind操作的挂载点目录dentry。下次循执行
   propagation_next()返回mount3，执行get_source(),dest是mount3,get_source()返回child_2，然后执行copy_tree()以child_2克隆生成child_3,
   接着执行mnt_set_mountpoint(mount3,dest_mp,child_3)设置mount3和child_3构成父子关系，即child3->mnt_parent=mount3,child_3的挂载点目录。
   child3就是mount3的source mount，mount3是dest mount，一一对应。是dest_mp->dentry，即本次mount bind操作的挂载点目录dentry。

   简单总结，get_soucrce()返回的是dest在shared mount组前一个mount的对应的source mount,即last_src。share mount组的每个mountx
   (是slave mount组成员克隆母体的除外，如mount1)，都要照着get_soucrce()返回的last_src克隆生成一个child，last_src和child的关系是，二者
   是同一个share mount组的，child和mountx是父子关系，即child->mnt_parent=mountx。child的挂载点目录dentry是本次mount bind操作
   的挂载点目录dentry。
*/
static struct mount *get_source(struct mount *dest,
				struct mount *last_dest,
				struct mount *last_src,
				int *type)
{
	struct mount *p_last_src = NULL;
	struct mount *p_last_dest = NULL;


	while (last_dest != dest->mnt_master) {
		p_last_dest = last_dest;
		p_last_src = last_src;
		last_dest = last_dest->mnt_master;
		last_src = last_src->mnt_master;
	}

	if (p_last_dest) {
		do {
			p_last_dest = next_peer(p_last_dest);
		} while (IS_MNT_NEW(p_last_dest));
		/* is that a peer of the earlier? */
		if (dest == p_last_dest) {
			*type = CL_MAKE_SHARED;
			return p_last_src;
		}
	}
	/* slave of the earlier, then */
	*type = CL_SLAVE;
	/* beginning of peer group among the slaves? */
	if (IS_MNT_SHARED(dest))
		*type |= CL_MAKE_SHARED;
	return last_src;
}

/*
 * mount 'source_mnt' under the destination 'dest_mnt' at
 * dentry 'dest_dentry'. And propagate that mount to
 * all the peer and slave mounts of 'dest_mnt'.
 * Link all the new mounts into a propagation tree headed at
 * source_mnt. Also link all the new mounts using ->mnt_list
 * headed at source_mnt's ->mnt_list
 *
 * @dest_mnt: destination mount.
 * @dest_dentry: destination dentry.
 * @source_mnt: source mount.
 * @tree_list : list of heads of trees to be attached.
 */
//遍历dest mount树下的slave  mount组或者share mount组的所有mount，每个这种mount作为dest mount^, 同时以source mount为克隆母体
//克隆生成一个mount，作为source mount^，dest mount^和source mount^构成父子关系，二者不是本次mount 挂载的原始source mount和dest mount
//只是中途生成的，有区别。这个就是传播mount:本次与dest mount同一个slave 或者share mount组的mount，要作为dest mount^，本次mount挂载的
//原始source mount要作为克隆母体，一一为dest mount^们克隆生成一个source mount^，这就是mount组传播mount的原理。克隆生成的mount
//添加到tree_list链表，稍后执行commit_tree()再把这些mount链表添加到各个mount结构有关的链表。
int propagate_mnt(struct mount *dest_mnt, struct mountpoint *dest_mp,
		    struct mount *source_mnt, struct list_head *tree_list)
{
	struct user_namespace *user_ns = current->nsproxy->mnt_ns->user_ns;
	struct mount *m, *child;
	int ret = 0;
	struct mount *prev_dest_mnt = dest_mnt;
	struct mount *prev_src_mnt  = source_mnt;
	LIST_HEAD(tmp_list);

//返回peer group即同是shared属性mount组中的下一个mount或者同是slave属性mount组的下一个mount。貌似mount结构有shared属性的mount
//都靠其mnt_share成员构成一个单向链表。有slave属性的mount靠其mnt_slave成员构成一个单向链表。propagation_next()函数
//貌似就是以本次mount命令的dest mount结构为开始，通过mount结构的mnt_share和mnt_slave成员，遍历所有同一个属性组所有的mount结构赋予m变量
	for (m = propagation_next(dest_mnt, dest_mnt); m;
			m = propagation_next(m, dest_mnt)) {
		int type;
		struct mount *source;
        //如果是本次挂载新生成的mount，不用传播，mount bind操作的之前已经克隆生成了source mount，与原目录的mount是同一个share 组，这里会遍历到
		if (IS_MNT_NEW(m))
			continue;

		source =  get_source(m, prev_dest_mnt, prev_src_mnt, &type);

		/* Notice when we are propagating across user namespaces */
		if (m->mnt_ns->user_ns != user_ns)
			type |= CL_UNPRIVILEGED;

     /*执行clone_mnt()照着source克隆一个mount，即child mount。设置child mount的mnt_mountpoint为克隆母体的mnt_mountpoint。
       还有一个要点，设置child mount的child->mnt.mnt_root是克隆母体的source->mnt.mnt_root。最后返回克隆mount于child*/
		child = copy_tree(source, source->mnt.mnt_root, type);
		if (IS_ERR(child)) {
			ret = PTR_ERR(child);
			list_splice(tree_list, tmp_list.prev);
			goto out;
		}

        /*dest_mp->m_dentry是本次mount挂载点终极目录dentry，m->mnt.mnt_root是m这个mount结构代表的块设备文件系统的根目录
          只有dest_mp->m_dentry是m代表的文件系统下的目录dentry才有效*/
		if (is_subdir(dest_mp->m_dentry, m->mnt.mnt_root)) {
        /*针对克隆生成mount结构child设置父子关系。克隆生成的child是"source mount^"，m是挂载点目录的块设备的mount结构，就是"dest mount^"
         m是child的parent。dest_mp->m_dentry是child挂载点目录dentry，那dest_mp->m_dentry肯定也得是"dest mount"即m这个mount结构代表
         的块设备文件系统的根目录下的一个目录，这点没得商量。所以if (is_subdir(dest_mp->m_dentry, m->mnt.mnt_root))必须要有。
         */
        //这里我有个大的疑问???????????设置克隆生成的mount即child的挂载点目录!简单来说，本次的mount bind命令的挂载源目录也要挂载到与
        //挂载点目录的dest mount同一个mount share共享组的其他mount。这样不是应该设置child的挂载点目录与dest mount^同样的挂载点?????
        //即设置child->mnt_mountpoint = m->mnt_mountpoint?但实际设置child->mnt_mountpoint时本次mount bind操作的挂载点目录。并且我查看
        //cat /proc/self/mountinfo看到的信息，凡是mount组传播生成的mount，它的挂载点目录与他父mount是就是同一个，说明二者的mount的
        //mnt_mountpoint就是同一个呀?????有很多疑问，我觉个查看mount信息的内核函数show_mountinfo->seq_path_root()应该能解答疑惑
			mnt_set_mountpoint(m, dest_mp, child);
            /*克隆生成child暂时添加到tree_list链表，在attach_recursive_mnt最后，会把tree_list链表上的克隆生成的mount取出来，执行
             attach_recursive_mnt，把mount结构添加到系统*/
			list_add_tail(&child->mnt_hash, tree_list);
		} else {
			 // This can happen if the parent mount was bind mounted
			 // on some subdirectory of a shared/slave mount.
			/*克隆生成的child无效，先放到tmp_list链表，该函数最后再执行umount_tree()销毁这些mount*/
			list_add_tail(&child->mnt_hash, &tmp_list);
		}
        
        /*prev_dest_mnt指向propagation_next()遍历dest mount的slave mount组或者share mount组返回的mount*/
		prev_dest_mnt = m;
        /*prev_src_mnt指向克隆生成的mount，即child*/
		prev_src_mnt  = child;
	}
out:
	br_write_lock(&vfsmount_lock);
	while (!list_empty(&tmp_list)) {
		child = list_first_entry(&tmp_list, struct mount, mnt_hash);
		umount_tree(child, 0);
	}
	br_write_unlock(&vfsmount_lock);
	return ret;
}

/*
 * return true if the refcount is greater than count
 */
static inline int do_refcount_check(struct mount *mnt, int count)
{
	int mycount = mnt_get_count(mnt) - mnt->mnt_ghosts;
	return (mycount > count);
}

/*
 * check if the mount 'mnt' can be unmounted successfully.
 * @mnt: the mount to be checked for unmount
 * NOTE: unmounting 'mnt' would naturally propagate to all
 * other mounts its parent propagates to.
 * Check if any of these mounts that **do not have submounts**
 * have more references than 'refcnt'. If so return busy.
 *
 * vfsmount lock must be held for write
 */
int propagate_mount_busy(struct mount *mnt, int refcnt)
{
	struct mount *m, *child;
	struct mount *parent = mnt->mnt_parent;
	int ret = 0;

	if (mnt == parent)
		return do_refcount_check(mnt, refcnt);

	/*
	 * quickly check if the current mount can be unmounted.
	 * If not, we don't have to go checking for all other
	 * mounts
	 */
	if (!list_empty(&mnt->mnt_mounts) || do_refcount_check(mnt, refcnt))
		return 1;

	for (m = propagation_next(parent, parent); m;
	     		m = propagation_next(m, parent)) {
		child = __lookup_mnt(&m->mnt, mnt->mnt_mountpoint, 0);
		if (child && list_empty(&child->mnt_mounts) &&
		    (ret = do_refcount_check(child, 1)))
			break;
	}
	return ret;
}

/*
 * NOTE: unmounting 'mnt' naturally propagates to all other mounts its
 * parent propagates to.
 */
static void __propagate_umount(struct mount *mnt)
{
	struct mount *parent = mnt->mnt_parent;
	struct mount *m;

	BUG_ON(parent == mnt);

	for (m = propagation_next(parent, parent); m;
			m = propagation_next(m, parent)) {

		struct mount *child = __lookup_mnt(&m->mnt,
					mnt->mnt_mountpoint, 0);
		/*
		 * umount the child only if the child has no
		 * other children
		 */
		if (child && list_empty(&child->mnt_mounts))
			list_move_tail(&child->mnt_hash, &mnt->mnt_hash);
	}
}

/*
 * collect all mounts that receive propagation from the mount in @list,
 * and return these additional mounts in the same list.
 * @list: the list of mounts to be unmounted.
 *
 * vfsmount lock must be held for write
 */
int propagate_umount(struct list_head *list)
{
	struct mount *mnt;

	list_for_each_entry(mnt, list, mnt_hash)
		__propagate_umount(mnt);
	return 0;
}
