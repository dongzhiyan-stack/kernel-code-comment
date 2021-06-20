#ifndef _LINUX_CGROUP_H
#define _LINUX_CGROUP_H
/*
 *  cgroup interface
 *
 *  Copyright (C) 2003 BULL SA
 *  Copyright (C) 2004-2006 Silicon Graphics, Inc.
 *
 */

#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/nodemask.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/cgroupstats.h>
#include <linux/prio_heap.h>
#include <linux/rwsem.h>
#include <linux/idr.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>
#include <linux/fs.h>

#ifdef CONFIG_CGROUPS

struct cgroupfs_root;
struct cgroup_subsys;
struct inode;
struct cgroup;
struct css_id;
struct eventfd_ctx;

extern int cgroup_init_early(void);
extern int cgroup_init(void);
extern void cgroup_fork(struct task_struct *p);
extern void cgroup_post_fork(struct task_struct *p);
extern void cgroup_exit(struct task_struct *p, int run_callbacks);
extern int cgroupstats_build(struct cgroupstats *stats,
				struct dentry *dentry);
extern int cgroup_load_subsys(struct cgroup_subsys *ss);
extern void cgroup_unload_subsys(struct cgroup_subsys *ss);

extern int proc_cgroup_show(struct seq_file *, void *);

/*
 * Define the enumeration of all cgroup subsystems.
 *
 * We define ids for builtin subsystems and then modular ones.
 */
#define SUBSYS(_x) _x ## _subsys_id,
enum cgroup_subsys_id {
#define IS_SUBSYS_ENABLED(option) IS_BUILTIN(option)
//这个头文件就是包含SUBSYS(cpu_cgroup)、SUBSYS(mem_cgroup)这些限制结构体，
#include <linux/cgroup_subsys.h>
#undef IS_SUBSYS_ENABLED
	CGROUP_BUILTIN_SUBSYS_COUNT,

	__CGROUP_SUBSYS_TEMP_PLACEHOLDER = CGROUP_BUILTIN_SUBSYS_COUNT - 1,

#define IS_SUBSYS_ENABLED(option) IS_MODULE(option)
//这个头文件就是包含SUBSYS(cpu_cgroup)、SUBSYS(mem_cgroup)这些限制结构体，SUBSYS(block)
#include <linux/cgroup_subsys.h>
#undef IS_SUBSYS_ENABLED
	CGROUP_SUBSYS_COUNT,//应该是cgroup子系统总的个数吧???就是限制cpu、mem、io的系统。每个系统占一个编号,cpu是2,block是8
};
#undef SUBSYS

/* Per-subsystem/per-cgroup state maintained by the system. */
//分配是在每个子系统struct cgroup_subsys的css_alloc函数，mem的是，mem_cgroup_css_alloc，cpu的是cpu_cgroup_css_alloc

//通过struct cgroup的struct cgroup_subsys_state *subsys[cpu_cgroup_subsys_id]成员，得到cpu cgroup对应的
//struct cgroup_subsys_state结构，再由struct cgroup_subsys_state的container_of操作，得到struct task_group
//struct cgroup_subsys_state真的是连接struct cgroup、struct task_group的桥梁呀
/*每个cpu、blkio等cgroup控制结构都有独立的 cgroup_subsys_state结构，每次mkdir 创建cgroup目录都会创建。见cgroup_create
并不是 cgroup_subsys_state个数与cgroup子系统个数相等*/
struct cgroup_subsys_state {
//cgroup目录下mkdir 创建cgroup目录时执行cgroup_create(),分配struct cgroup,顺带还分配cgroup_subsys_state
//struct cgroup和cgroup_subsys_state一一对应
	/*
	 * The cgroup that this subsystem is attached to. Useful
	 * for subsystems that want to know about the cgroup
	 * hierarchy structure
	 */
	//指向对应的cgroup结构，创建cgroup目录时执行cgroup_create->init_cgroup_css()中赋值
	struct cgroup *cgroup;

	/*
	 * State maintained by the cgroup system to allow subsystems
	 * to be "busy". Should be accessed via css_get(),
	 * css_tryget() and css_put().
	 */

	atomic_t refcnt;

	unsigned long flags;
	/* ID for this css, if possible */
	struct css_id __rcu *id;

	/* Used to put @cgroup->dentry on the last css_put() */
	struct work_struct dput_work;
};

/* bits in struct cgroup_subsys_state flags field */
enum {
	CSS_ROOT	= (1 << 0), /* this CSS is the root of the subsystem */
	CSS_ONLINE	= (1 << 1), /* between ->css_online() and ->css_offline() */
};

/* Caller must verify that the css is not for root cgroup */
static inline void __css_get(struct cgroup_subsys_state *css, int count)
{
	atomic_add(count, &css->refcnt);
}

/*
 * Call css_get() to hold a reference on the css; it can be used
 * for a reference obtained via:
 * - an existing ref-counted reference to the css
 * - task->cgroups for a locked task
 */

static inline void css_get(struct cgroup_subsys_state *css)
{
	/* We don't need to reference count the root state */
	if (!(css->flags & CSS_ROOT))
		__css_get(css, 1);
}

/*
 * Call css_tryget() to take a reference on a css if your existing
 * (known-valid) reference isn't already ref-counted. Returns false if
 * the css has been destroyed.
 */

extern bool __css_tryget(struct cgroup_subsys_state *css);
static inline bool css_tryget(struct cgroup_subsys_state *css)
{
	if (css->flags & CSS_ROOT)
		return true;
	return __css_tryget(css);
}

/*
 * css_put() should be called to release a reference taken by
 * css_get() or css_tryget()
 */

extern void __css_put(struct cgroup_subsys_state *css);
static inline void css_put(struct cgroup_subsys_state *css)
{
	if (!(css->flags & CSS_ROOT))
		__css_put(css);
}

/* bits in struct cgroup flags field */
enum {
	/* Control Group is dead */
	CGRP_REMOVED,
	/*
	 * Control Group has previously had a child cgroup or a task,
	 * but no longer (only if CGRP_NOTIFY_ON_RELEASE is set)
	 */
	CGRP_RELEASABLE,
	/* Control Group requires release notifications to userspace */
	CGRP_NOTIFY_ON_RELEASE,
	/*
	 * Clone the parent's configuration when creating a new child
	 * cpuset cgroup.  For historical reasons, this option can be
	 * specified at mount time and thus is implemented here.
	 */
	CGRP_CPUSET_CLONE_CHILDREN,
	/* see the comment above CGRP_ROOT_SANE_BEHAVIOR for details */
	CGRP_SANE_BEHAVIOR,
};

struct cgroup_name {
	struct rcu_head rcu_head;
	char name[];
};
//cgroup_create()分配并初始化。以cpu cgroup为例，顶层的控制目录cpu，就对应一个struct cgroup吧?????????然后在这个目录mkdir test目录，
//应该又会创建一个struct cgroup。最顶层的cgroup结构包含在struct cgroupfs_root里，一个目录一个struct cgroup，记住很关键
struct cgroup {
	unsigned long flags;		/* "unsigned long" so bitops work */

	/*
	 * count users of this cgroup. >0 means busy, but doesn't
	 * necessarily indicate the number of tasks in the cgroup
	 */
	atomic_t count;//cgroup引用计数

	int id;				/* ida allocated in-hierarchy ID */

	/*
	 * We link our 'sibling' struct into our parent's 'children'.
	 * Our children link their 'sibling' into our 'children'.
	 */
	struct list_head sibling;	/* my parent's children */
	struct list_head children;	/* my children */
	struct list_head files;		/* my files */
    //父struct cgroup结构，一个目录对应一个struct cgroup结构，父子目录的struct cgroup结构彼此构成联系
	struct cgroup *parent;		/* my parent */
    //每一层cgroup目录的dentry，如果是顶层的cgroup，那就是cpu cgroup子系统根目录的dentry。cgroup_create()中赋值
	struct dentry *dentry;		/* cgroup fs entry, RCU protected */

	/*
	 * This is a copy of dentry->d_name, and it's needed because
	 * we can't use dentry->d_name in cgroup_path().
	 *
	 * You must acquire rcu_read_lock() to access cgrp->name, and
	 * the only place that can change it is rename(), which is
	 * protected by parent dir's i_mutex.
	 *
	 * Normally you should use cgroup_name() wrapper rather than
	 * access it directly.
	 */
	struct cgroup_name __rcu *name;

	/* Private pointers for each registered subsystem */
  //创建cgroup目录时执行cgroup_create->init_cgroup_css()中赋值,只赋值该cgroup系统的，比如当前是cpu cgroup，
  //则只会subsys[2]= struct cgroup_subsys_state *css，其他struct cgroup_subsys_state *subsys[]估计都是NULL，浪费了
  //通过struct cgroup_subsys_state *subsys[x]找到实际的控制实体，比如限制CPU的struct task_group结构体。
  //比如这个cgroup代表cpu cgroup，假设cpu cgroup在该数组的下标是2，则先得到到subsys[2]指向的struct cgroup_subsys_state指针，
  //再通过container_of(cgroup_subsys_state)，就找到了cpu的struct task_group结构体
	struct cgroup_subsys_state *subsys[CGROUP_SUBSYS_COUNT];//cgroup_create()->init_cgroup_css()中赋值

    //每个cgroup系统一个struct cgroupfs_root，就像根目录dentry一样。cgroup_init_subsys()中指向rootnode
	struct cgroupfs_root *root;

	/*
	 * List of cg_cgroup_links pointing at css_sets with
	 * tasks in this cgroup. Protected by css_set_lock
	 */
	//struct cg_cgroup_link靠其成员struct list_head cgrp_link_list添加到struct cgroup的css_sets链表，
    //这样struct cg_cgroup_link与struct cgroup建立了联系。find_css_set()函数详细讲解他们的关系。
    //进程task_struct结构、struct css_set、struct cg_cgroup_link、进程绑定的struct cgroup一一对应
    //然后每个struct cgroup又与task_cgroup或者mem_cgroup控制单元一一对应，这样通过每个进程的task_struct
    //结构就能找到这个进程绑定的task_cgroup或者mem_cgroup控制单元
	struct list_head css_sets;

	struct list_head allcg_node;	/* cgroupfs_root->allcg_list */
	struct list_head cft_q_node;	/* used during cftype add/rm */

	/*
	 * Linked list running through all cgroups that can
	 * potentially be reaped by the release agent. Protected by
	 * release_list_lock
	 */
	struct list_head release_list;

	/*
	 * list of pidlists, up to two for each namespace (one for procs, one
	 * for tasks); created on demand.
	 */
	struct list_head pidlists;
	struct mutex pidlist_mutex;

	/* For RCU-protected deletion */
	struct rcu_head rcu_head;
	struct work_struct free_work;

	/* List of events which userspace want to receive */
	struct list_head event_list;
	spinlock_t event_list_lock;

	/* directory xattrs */
	struct simple_xattrs xattrs;
};

#define MAX_CGROUP_ROOT_NAMELEN 64

/* cgroupfs_root->flags */
enum {
	/*
	 * Unfortunately, cgroup core and various controllers are riddled
	 * with idiosyncrasies and pointless options.  The following flag,
	 * when set, will force sane behavior - some options are forced on,
	 * others are disallowed, and some controllers will change their
	 * hierarchical or other behaviors.
	 *
	 * The set of behaviors affected by this flag are still being
	 * determined and developed and the mount option for this flag is
	 * prefixed with __DEVEL__.  The prefix will be dropped once we
	 * reach the point where all behaviors are compatible with the
	 * planned unified hierarchy, which will automatically turn on this
	 * flag.
	 *
	 * The followings are the behaviors currently affected this flag.
	 *
	 * - Mount options "noprefix" and "clone_children" are disallowed.
	 *   Also, cgroupfs file cgroup.clone_children is not created.
	 *
	 * - When mounting an existing superblock, mount options should
	 *   match.
	 *
	 * - Remount is disallowed.
	 *
	 * - memcg: use_hierarchy is on by default and the cgroup file for
	 *   the flag is not created.
	 *
	 * The followings are planned changes.
	 *
	 * - release_agent will be disallowed once replacement notification
	 *   mechanism is implemented.
	 */
	CGRP_ROOT_SANE_BEHAVIOR	= (1 << 0),

	CGRP_ROOT_NOPREFIX	= (1 << 1), /* mounted subsystems have no named prefix */
	CGRP_ROOT_XATTR		= (1 << 2), /* supports extended attributes */
};

/*
 * A cgroupfs_root represents the root of a cgroup hierarchy, and may be
 * associated with a superblock to form an active hierarchy.  This is
 * internal to cgroup core.  Don't access directly from controllers.
 */
struct cgroupfs_root {//每个cgroup子系统有自己唯一的cgroupfs_root
	struct super_block *sb;

	/*
	 * The bitmask of subsystems intended to be attached to this
	 * hierarchy
	 */
	//cpu、memory、blkio的依次是0x6 0x8 0x80,为什么cpu的是0x6,两个bit位是1呢?应该是因为cpu的实际包含"cpu"和"cpuacct"两个cgroup子系统吧
	unsigned long subsys_mask;

	/* Unique id for this hierarchy. */
	int hierarchy_id;//cpu、blkio、memory的依次是3、4、9

	/* The bitmask of subsystems currently attached to this hierarchy */
	unsigned long actual_subsys_mask;

	/* A list running through the attached subsystems */
    //cgroup_init_subsys()中把cgroup_subsys的成员sibling添加到struct cgroupfs_root的subsys_list链表
	struct list_head subsys_list;//cgroup_init_subsys中把从cpu、mem、block等cgroup_subsys添加到subsys_list链表

	/* The root cgroup for this hierarchy */
	struct cgroup top_cgroup;//顶层的cgroup

	/* Tracks how many cgroups are currently defined in hierarchy.*/
	int number_of_cgroups;

	/* A list running through the active hierarchies */
	struct list_head root_list;

	/* All cgroups on this root, cgroup_mutex protected */
	struct list_head allcg_list;

	/* Hierarchy-specific flags */
	unsigned long flags;

	/* IDs for cgroups in this hierarchy */
	struct ida cgroup_ida;

	/* The path to use for release notifications. */
	char release_agent_path[PATH_MAX];

	/* The name for this hierarchy - may be empty */
	char name[MAX_CGROUP_ROOT_NAMELEN];
};

/*
 * A css_set is a structure holding pointers to a set of
 * cgroup_subsys_state objects. This saves space in the task struct
 * object and speeds up fork()/exit(), since a single inc/dec and a
 * list_add()/del() can bump the reference count on the entire cgroup
 * set for a task.
 */
//进程绑定struct cgroup后，会把绑定的struct cgroup对应的struct cg_cgroup_link添加到
//task_struct的struct css_set  *cgroups的cg_links链表
struct css_set {

	/* Reference count */
	atomic_t refcount;

	/*
	 * List running through all cgroup groups in the same hash
	 * slot. Protected by css_set_lock
	 */
	struct hlist_node hlist;//find_css_set()中通过css_set的hlist成员把css_set添加到css_set_table

	/*
	 * List running through all tasks using this cgroup
	 * group. Protected by css_set_lock
	 */
	//进程绑定cgroup时，cgroup_attach_task->cgroup_task_migrate函数中，把task_struct结构的cg_list添加到struct css_set的tasks链表
    //而之前task_struct结构的struct css_set __rcu *cgroups指向这个struct css_set结构，相互连接，这关系真是错综复杂呀
	struct list_head tasks;

	/*
	 * List of cg_cgroup_link objects on link chains from
	 * cgroups referenced from this css_set. Protected by
	 * css_set_lock
	 */
 //进程绑定struct cgroup后，会把绑定的struct cgroup对应的struct cg_cgroup_link添加到task_struct的struct css_set  *cgroups的cg_links链表
 //struct cg_cgroup_link靠其成员struct list_head cg_link_list添加到struct css_set的cg_links，这样struct cg_cgroup_link
 //和struct css_set建立了联系。进程task_struct结构、struct css_set、struct cg_cgroup_link、进程绑定的struct cgroup一一对应
// find_css_set()函数详细讲解他们的关系
 //然后每个struct cgroup又与task_cgroup或者mem_cgroup控制单元一一对应，这样通过每个进程的task_struct
 //结构就能找到这个进程绑定的task_cgroup或者mem_cgroup控制单元
 
   struct list_head cg_links;//struct cg_cgroup_link靠其成员struct list_head cg_link_list添加到到struct css_set的cg_links

	/*
	 * Set of subsystem states, one for each subsystem. This array
	 * is immutable after creation apart from the init_css_set
	 * during subsystem registration (at boot time) and modular subsystem
	 * loading/unloading.
	 */
	//进程绑定的cpu、mem等cgroup的struct cgroup_subsys_state，通过subsys[cgroup subsys id]二者，可以找到对应的
	//cgroup子系统的struct cgroup_subsys_state，再container_of(cgroup_subsys_state)就能找到对应的task_group或者mem_cgroup结构

    //来自进程绑定的cgroup目录的struct cgroup的struct cgroup_subsys_state
	struct cgroup_subsys_state *subsys[CGROUP_SUBSYS_COUNT];

	/* For RCU-protected deletion */
	struct rcu_head rcu_head;
};

/*
 * cgroup_map_cb is an abstract callback API for reporting map-valued
 * control files
 */

struct cgroup_map_cb {
	int (*fill)(struct cgroup_map_cb *cb, const char *key, u64 value);
	void *state;
};

/*
 * struct cftype: handler definitions for cgroup control files
 *
 * When reading/writing to a file:
 *	- the cgroup to use is file->f_dentry->d_parent->d_fsdata
 *	- the 'cftype' of the file is file->f_dentry->d_fsdata
 */

/* cftype->flags */
#define CFTYPE_ONLY_ON_ROOT	(1U << 0)	/* only create on root cg */
#define CFTYPE_NOT_ON_ROOT	(1U << 1)	/* don't create on root cg */
#define CFTYPE_INSANE		(1U << 2)	/* don't create if sane_behavior */

#define MAX_CFTYPE_NAME		64

/*
struct cftype主要有3类
1  cgroup基本的struct cftype数组，如"tasks"、"release_agent"等cgroup文件，这些cgroup文件创建在cgroup_create->
     cgroup_populate_dir->cgroup_addrm_files(cgrp, NULL, files, true)
2  cgroup子系统cgroup_subsys结构体默认指定的struct cftype数组，如struct cgroup_subsys cpu_cgroup_subsys[]的struct cftype cpu_files[]，
     这些cgroup文件的创建在:cgroup_create->cgroup_populate_dir->cgroup_addrm_files(cgrp, ss, set->cfts, true)
3  cgroup子系统cgroup_subsys专门添加的struct cftype数组，赋值见blkcg_policy_register->cgroup_add_cftypes()对block层流控的
   struct cftype throtl_files[]数组，这些cgroup文件的创建在cgroup_create->cgroup_populate_dir
     ->cgroup_addrm_files(cgrp, ss, set->cfts, true).
*/
//代表cgroup下的一个文件，比如cpu cgroup每个目录的基本文件"tasks"，控制进程运行时间的cfs_quota_us和cpu_cfs_period文件
//struct cftype包含了该文件的读写控制函数，如echo设置进程运行时间要调用的write函数
//cpu cgroup特有的控制文件包含在struct cftype cpu_files[]，内存的是struct cftype mem_cgroup_files[]
//每个cgroup子系统base控制文件是struct cftype files[]。上层读写cgroup文件，先调用vfs层的cgroup_file_write/cgroup_file_read
//然后再调用struct cftype注册具体每个cgroup文件的读写函数，
struct cftype {//
	/*
	 * By convention, the name should begin with the name of the
	 * subsystem, followed by a period.  Zero length string indicates
	 * end of cftype array.
	 */
	char name[MAX_CFTYPE_NAME];
    //mem cgroup时，代表了设置mem参数的行为，看mem_cgroup_write函数
	int private;
	/*
	 * If not 0, file mode is set to this value, otherwise it will
	 * be figured out automatically
	 */
	umode_t mode;

	/*
	 * If non-zero, defines the maximum length of string that can
	 * be passed to write_string; defaults to 64
	 */
	size_t max_write_len;

	/* CFTYPE_* flags */
	unsigned int flags;
    //cfs_quota_us、cpu_cfs_period这些文件的open
	int (*open)(struct inode *inode, struct file *file);
	ssize_t (*read)(struct cgroup *cgrp, struct cftype *cft,
			struct file *file,
			char __user *buf, size_t nbytes, loff_t *ppos);
	/*
	 * read_u64() is a shortcut for the common case of returning a
	 * single integer. Use it in place of read()
	 */
     //cfs_quota_us、cpu_cfs_period这些文件的read
	u64 (*read_u64)(struct cgroup *cgrp, struct cftype *cft);
	/*
	 * read_s64() is a signed version of read_u64()
	 */
	s64 (*read_s64)(struct cgroup *cgrp, struct cftype *cft);
	/*
	 * read_map() is used for defining a map of key/value
	 * pairs. It should call cb->fill(cb, key, value) for each
	 * entry. The key/value pairs (and their ordering) should not
	 * change between reboots.
	 */
	int (*read_map)(struct cgroup *cont, struct cftype *cft,
			struct cgroup_map_cb *cb);
	/*
	 * read_seq_string() is used for outputting a simple sequence
	 * using seqfile.
	 */
	int (*read_seq_string)(struct cgroup *cont, struct cftype *cft,
			       struct seq_file *m);

	ssize_t (*write)(struct cgroup *cgrp, struct cftype *cft,
			 struct file *file,
			 const char __user *buf, size_t nbytes, loff_t *ppos);

	/*
	 * write_u64() is a shortcut for the common case of accepting
	 * a single integer (as parsed by simple_strtoull) from
	 * userspace. Use in place of write(); return 0 or error.
	 */
	//cfs_quota_us、cpu_cfs_period这些文件的write
	int (*write_u64)(struct cgroup *cgrp, struct cftype *cft, u64 val);
	/*
	 * write_s64() is a signed version of write_u64()
	 */
	int (*write_s64)(struct cgroup *cgrp, struct cftype *cft, s64 val);

	/*
	 * write_string() is passed a nul-terminated kernelspace
	 * buffer of maximum length determined by max_write_len.
	 * Returns 0 or -ve error code.
	 */
	int (*write_string)(struct cgroup *cgrp, struct cftype *cft,
			    const char *buffer);
	/*
	 * trigger() callback can be used to get some kick from the
	 * userspace, when the actual string written is not important
	 * at all. The private field can be used to determine the
	 * kick type for multiplexing.
	 */
	int (*trigger)(struct cgroup *cgrp, unsigned int event);

	int (*release)(struct inode *inode, struct file *file);

	/*
	 * register_event() callback will be used to add new userspace
	 * waiter for changes related to the cftype. Implement it if
	 * you want to provide this functionality. Use eventfd_signal()
	 * on eventfd to send notification to userspace.
	 */
	int (*register_event)(struct cgroup *cgrp, struct cftype *cft,
			struct eventfd_ctx *eventfd, const char *args);
	/*
	 * unregister_event() callback will be called when userspace
	 * closes the eventfd or on cgroup removing.
	 * This callback must be implemented, if you want provide
	 * notification functionality.
	 */
	void (*unregister_event)(struct cgroup *cgrp, struct cftype *cft,
			struct eventfd_ctx *eventfd);
};

/*
 * cftype_sets describe cftypes belonging to a subsystem and are chained at
 * cgroup_subsys->cftsets.  Each cftset points to an array of cftypes
 * terminated by zero length name.
 */
 
/*
每个cgroup子系统cgroup_subsys都有一个基础cftype_set，在cgroup_subsys结构体里。在cgroup_add_cftypes()还会再分配新的cftype_set。
每个cftype_set都靠其成员node添加到cgroup_subsys的cftsets链表，cftype_set的成员cfts指向对应的struct cftype数组，

start_kernel->cgroup_init_early->cgroup_init_subsys->cgroup_init_cftsets 操作cgroup子系统cgroup_subsys的基本cftype_set和cftype，如cpu
的struct cftype cpu_files[]

throtl_init->blkcg_policy_register->cgroup_add_cftypes  操作每个cgroup子系统cgroup_subsys特有的cftype_set和cftype，如block层流控的
cftype数组struct cftype throtl_files[]
*/
struct cftype_set {
    //cgroup_init_cftsets()中将cftype_set的node添加到cgroup_subsys的cftsets链表，将来可以通过cgroup_subsys的cftsets链表上的node
    //contained_of找到cftype_set，cftype_set的成员cfts指向cftype文件
    //cgroup_add_cftypes()中把block层流控的cftype数组throtl_files添加到block cgorup子系统blkio_subsys的cftsets链表
	struct list_head		node;	/* chained at subsys->cftsets */
    //cgroup_init_cftsets()中令cftype_set的cfts指向base_cftypes指向的cftype文件
    //cgroup_add_cftypes()中也会令cftype_set的cfts指向新添加的cftype数组，比如block cgroup流控的struct cftype throtl_files数组
	struct cftype			*cfts;
};

struct cgroup_scanner {
	struct cgroup *cg;
	int (*test_task)(struct task_struct *p, struct cgroup_scanner *scan);
	void (*process_task)(struct task_struct *p,
			struct cgroup_scanner *scan);
	struct ptr_heap *heap;
	void *data;
};

/*
 * See the comment above CGRP_ROOT_SANE_BEHAVIOR for details.  This
 * function can be called as long as @cgrp is accessible.
 */
static inline bool cgroup_sane_behavior(const struct cgroup *cgrp)
{
	return cgrp->root->flags & CGRP_ROOT_SANE_BEHAVIOR;
}

/* Caller should hold rcu_read_lock() */
static inline const char *cgroup_name(const struct cgroup *cgrp)
{
	return rcu_dereference(cgrp->name)->name;
}

int cgroup_add_cftypes(struct cgroup_subsys *ss, struct cftype *cfts);
int cgroup_rm_cftypes(struct cgroup_subsys *ss, struct cftype *cfts);

int cgroup_is_removed(const struct cgroup *cgrp);
bool cgroup_is_descendant(struct cgroup *cgrp, struct cgroup *ancestor);

int cgroup_path(const struct cgroup *cgrp, char *buf, int buflen);

int cgroup_task_count(const struct cgroup *cgrp);

/*
 * Control Group taskset, used to pass around set of tasks to cgroup_subsys
 * methods.
 */
struct cgroup_taskset;
struct task_struct *cgroup_taskset_first(struct cgroup_taskset *tset);
struct task_struct *cgroup_taskset_next(struct cgroup_taskset *tset);
struct cgroup *cgroup_taskset_cur_cgroup(struct cgroup_taskset *tset);
int cgroup_taskset_size(struct cgroup_taskset *tset);

/**
 * cgroup_taskset_for_each - iterate cgroup_taskset
 * @task: the loop cursor
 * @skip_cgrp: skip if task's cgroup matches this, %NULL to iterate through all
 * @tset: taskset to iterate
 */
#define cgroup_taskset_for_each(task, skip_cgrp, tset)			\
	for ((task) = cgroup_taskset_first((tset)); (task);		\
	     (task) = cgroup_taskset_next((tset)))			\
		if (!(skip_cgrp) ||					\
		    cgroup_taskset_cur_cgroup((tset)) != (skip_cgrp))

/*
 * Control Group subsystem type.
 * See Documentation/cgroups/cgroups.txt for details
 */
//struct cgroup_subsys *subsys[]每个数组成员代表一个cgroup系统，比如subsys[2]就是cpu cgroup的struct cgroup_subsys
//该结构与cgroup建立联系是在mount过程的rebind_subsystems()
//cpu cgroup的是struct cgroup_subsys cpu_cgroup_subsys，这个结构包含了该子系统的基本操作函数、ID、控制文件信息
//mem cgroup的是struct cgroup_subsys mem_cgroup_subsys
struct cgroup_subsys {//cgroup_init_subsys()中初始化cpu、mem、block的cgroup_subsys
    //cgroup_create()中创建cgroup目录分配，调用cpu cgroup的struct cgroup_subsys结构的cpu_cgroup_css_alloc()函数
    //分配cpu cgroup控制结构task_group,看着像是cpu cgroup下每创建一个目录，都会创建一个task_group呀
	struct cgroup_subsys_state *(*css_alloc)(struct cgroup *cgrp);
	int (*css_online)(struct cgroup *cgrp);
	void (*css_offline)(struct cgroup *cgrp);
	void (*css_free)(struct cgroup *cgrp);

	int (*can_attach)(struct cgroup *cgrp, struct cgroup_taskset *tset);
	void (*cancel_attach)(struct cgroup *cgrp, struct cgroup_taskset *tset);
	void (*attach)(struct cgroup *cgrp, struct cgroup_taskset *tset);
	void (*fork)(struct task_struct *task);
	void (*exit)(struct cgroup *cgrp, struct cgroup *old_cgrp,
		     struct task_struct *task);
	void (*bind)(struct cgroup *root);

	int subsys_id;// subsys id 子系统的ID，应该就是cpu、mem这些cgroup系统都独有的编号，cpu的好像是2
	int disabled;
	int early_init;
	/*
	 * True if this subsys uses ID. ID is not available before cgroup_init()
	 * (not available in early_init time.)
	 */
	bool use_id;

	/*
	 * If %false, this subsystem is properly hierarchical -
	 * configuration, resource accounting and restriction on a parent
	 * cgroup cover those of its children.  If %true, hierarchy support
	 * is broken in some ways - some subsystems ignore hierarchy
	 * completely while others are only implemented half-way.
	 *
	 * It's now disallowed to create nested cgroups if the subsystem is
	 * broken and cgroup core will emit a warning message on such
	 * cases.  Eventually, all subsystems will be made properly
	 * hierarchical and this will go away.
	 */
	bool broken_hierarchy;
	bool warned_broken_hierarchy;

#define MAX_CGROUP_TYPE_NAMELEN 32
	const char *name;

	/*
	 * Link to parent, and list entry in parent's children.
	 * Protected by cgroup_lock()
	 */
	struct cgroupfs_root *root;//cgroup_init_subsys()中赋值，指向rootnode
	struct list_head sibling;//cgroup_init_subsys()中把cgroup_subsys的成员sibling添加到struct cgroupfs_root的subsys_list链表
	/* used when use_id == true */
	struct idr idr;
	spinlock_t id_lock;

	/* list of cftype_sets */
    //cgroup_init_cftsets()中将cftype_set的node添加到cgroup_subsys的cftsets链表，将来可以通过cgroup_subsys的cftsets链表上的node
    //contained_of找到cftype_set，cftype_set的成员cfts指向cftype文件
	struct list_head cftsets;
	
	/* base cftypes, automatically [de]registered with subsys itself */
    //代表cgroup系统目录下的基本文件，就是cpuset_subsys或者blkio_subsys结构的base_cftypes成员指向的cftype文件
	struct cftype *base_cftypes;
    //cgroup_init_cftsets()中令base_cftset的cftype指向base_cftypes指向的cftype文件
	struct cftype_set base_cftset;

	/* should be defined only by modular subsystems */
	struct module *module;
};

#define SUBSYS(_x) extern struct cgroup_subsys _x ## _subsys;
#define IS_SUBSYS_ENABLED(option) IS_BUILTIN(option)
#include <linux/cgroup_subsys.h>
#undef IS_SUBSYS_ENABLED
#undef SUBSYS
//通过struct cgroup的struct cgroup_subsys_state *subsys[cpu_cgroup_subsys_id]成员，得到cpu cgroup对应的
//struct cgroup_subsys_state结构
static inline struct cgroup_subsys_state *cgroup_subsys_state(
	struct cgroup *cgrp, int subsys_id)
{
	return cgrp->subsys[subsys_id];
}

/**
 * task_css_set_check - obtain a task's css_set with extra access conditions
 * @task: the task to obtain css_set for
 * @__c: extra condition expression to be passed to rcu_dereference_check()
 *
 * A task's css_set is RCU protected, initialized and exited while holding
 * task_lock(), and can only be modified while holding both cgroup_mutex
 * and task_lock() while the task is alive.  This macro verifies that the
 * caller is inside proper critical section and returns @task's css_set.
 *
 * The caller can also specify additional allowed conditions via @__c, such
 * as locks used during the cgroup_subsys::attach() methods.
 */
#ifdef CONFIG_PROVE_RCU
extern struct mutex cgroup_mutex;
#define task_css_set_check(task, __c)					\
	rcu_dereference_check((task)->cgroups,				\
		lockdep_is_held(&(task)->alloc_lock) ||			\
		lockdep_is_held(&cgroup_mutex) || (__c))
#else
#define task_css_set_check(task, __c)					\
	rcu_dereference((task)->cgroups)
#endif

/**
 * task_subsys_state_check - obtain css for (task, subsys) w/ extra access conds
 * @task: the target task
 * @subsys_id: the target subsystem ID
 * @__c: extra condition expression to be passed to rcu_dereference_check()
 *
 * Return the cgroup_subsys_state for the (@task, @subsys_id) pair.  The
 * synchronization rules are the same as task_css_set_check().
 */
//根据task和subsys_id返回绑定的cpu、mem对应的cgroup的cgroup_subsys_state
//注意task_css_set_check((task), (__c))是一个整体，就是返回进程task_struct的struct css_set __rcu *cgroups成员
//然后再通过这个struct css_set的struct cgroup_subsys_state *subsys[subsys_id]获取绑定的
//cgroup subsys的struct cgroup_subsys_state，再contained_of(cgroup_subsys_state)得到对应的task_group或者mem_cgroup结构
#define task_subsys_state_check(task, subsys_id, __c)			\
	task_css_set_check((task), (__c))->subsys[(subsys_id)]

/**
 * task_css_set - obtain a task's css_set
 * @task: the task to obtain css_set for
 *
 * See task_css_set_check().
 */
static inline struct css_set *task_css_set(struct task_struct *task)
{
	return task_css_set_check(task, false);
}

/**
 * task_subsys_state - obtain css for (task, subsys)
 * @task: the target task
 * @subsys_id: the target subsystem ID
 *
 * See task_subsys_state_check().
 */
//根据进程task_struct和subsys_id，返回绑定的cgroup subsys系统的struct cgroup_subsys_state
//有了struct cgroup_subsys_state，就能contained_of(cgroup_subsys_state)获取具体的task_group或者mem_cgroup结构
static inline struct cgroup_subsys_state *
task_subsys_state(struct task_struct *task, int subsys_id)
{
	return task_subsys_state_check(task, subsys_id, false);
}

static inline struct cgroup* task_cgroup(struct task_struct *task,
					       int subsys_id)
{
	return task_subsys_state(task, subsys_id)->cgroup;
}

/**
 * cgroup_for_each_child - iterate through children of a cgroup
 * @pos: the cgroup * to use as the loop cursor
 * @cgroup: cgroup whose children to walk
 *
 * Walk @cgroup's children.  Must be called under rcu_read_lock().  A child
 * cgroup which hasn't finished ->css_online() or already has finished
 * ->css_offline() may show up during traversal and it's each subsystem's
 * responsibility to verify that each @pos is alive.
 *
 * If a subsystem synchronizes against the parent in its ->css_online() and
 * before starting iterating, a cgroup which finished ->css_online() is
 * guaranteed to be visible in the future iterations.
 */
#define cgroup_for_each_child(pos, cgroup)				\
	list_for_each_entry_rcu(pos, &(cgroup)->children, sibling)

struct cgroup *cgroup_next_descendant_pre(struct cgroup *pos,
					  struct cgroup *cgroup);
struct cgroup *cgroup_rightmost_descendant(struct cgroup *pos);

/**
 * cgroup_for_each_descendant_pre - pre-order walk of a cgroup's descendants
 * @pos: the cgroup * to use as the loop cursor
 * @cgroup: cgroup whose descendants to walk
 *
 * Walk @cgroup's descendants.  Must be called under rcu_read_lock().  A
 * descendant cgroup which hasn't finished ->css_online() or already has
 * finished ->css_offline() may show up during traversal and it's each
 * subsystem's responsibility to verify that each @pos is alive.
 *
 * If a subsystem synchronizes against the parent in its ->css_online() and
 * before starting iterating, and synchronizes against @pos on each
 * iteration, any descendant cgroup which finished ->css_online() is
 * guaranteed to be visible in the future iterations.
 *
 * In other words, the following guarantees that a descendant can't escape
 * state updates of its ancestors.
 *
 * my_online(@cgrp)
 * {
 *	Lock @cgrp->parent and @cgrp;
 *	Inherit state from @cgrp->parent;
 *	Unlock both.
 * }
 *
 * my_update_state(@cgrp)
 * {
 *	Lock @cgrp;
 *	Update @cgrp's state;
 *	Unlock @cgrp;
 *
 *	cgroup_for_each_descendant_pre(@pos, @cgrp) {
 *		Lock @pos;
 *		Verify @pos is alive and inherit state from @pos->parent;
 *		Unlock @pos;
 *	}
 * }
 *
 * As long as the inheriting step, including checking the parent state, is
 * enclosed inside @pos locking, double-locking the parent isn't necessary
 * while inheriting.  The state update to the parent is guaranteed to be
 * visible by walking order and, as long as inheriting operations to the
 * same @pos are atomic to each other, multiple updates racing each other
 * still result in the correct state.  It's guaranateed that at least one
 * inheritance happens for any cgroup after the latest update to its
 * parent.
 *
 * If checking parent's state requires locking the parent, each inheriting
 * iteration should lock and unlock both @pos->parent and @pos.
 *
 * Alternatively, a subsystem may choose to use a single global lock to
 * synchronize ->css_online() and ->css_offline() against tree-walking
 * operations.
 */
#define cgroup_for_each_descendant_pre(pos, cgroup)			\
	for (pos = cgroup_next_descendant_pre(NULL, (cgroup)); (pos);	\
	     pos = cgroup_next_descendant_pre((pos), (cgroup)))

struct cgroup *cgroup_next_descendant_post(struct cgroup *pos,
					   struct cgroup *cgroup);

/**
 * cgroup_for_each_descendant_post - post-order walk of a cgroup's descendants
 * @pos: the cgroup * to use as the loop cursor
 * @cgroup: cgroup whose descendants to walk
 *
 * Similar to cgroup_for_each_descendant_pre() but performs post-order
 * traversal instead.  Note that the walk visibility guarantee described in
 * pre-order walk doesn't apply the same to post-order walks.
 */
#define cgroup_for_each_descendant_post(pos, cgroup)			\
	for (pos = cgroup_next_descendant_post(NULL, (cgroup)); (pos);	\
	     pos = cgroup_next_descendant_post((pos), (cgroup)))

/* A cgroup_iter should be treated as an opaque object */
struct cgroup_iter {
	struct list_head *cg_link;
	struct list_head *task;
};

/*
 * To iterate across the tasks in a cgroup:
 *
 * 1) call cgroup_iter_start to initialize an iterator
 *
 * 2) call cgroup_iter_next() to retrieve member tasks until it
 *    returns NULL or until you want to end the iteration
 *
 * 3) call cgroup_iter_end() to destroy the iterator.
 *
 * Or, call cgroup_scan_tasks() to iterate through every task in a
 * cgroup - cgroup_scan_tasks() holds the css_set_lock when calling
 * the test_task() callback, but not while calling the process_task()
 * callback.
 */
void cgroup_iter_start(struct cgroup *cgrp, struct cgroup_iter *it);
struct task_struct *cgroup_iter_next(struct cgroup *cgrp,
					struct cgroup_iter *it);
void cgroup_iter_end(struct cgroup *cgrp, struct cgroup_iter *it);
int cgroup_scan_tasks(struct cgroup_scanner *scan);
int cgroup_attach_task_all(struct task_struct *from, struct task_struct *);
int cgroup_transfer_tasks(struct cgroup *to, struct cgroup *from);

/*
 * CSS ID is ID for cgroup_subsys_state structs under subsys. This only works
 * if cgroup_subsys.use_id == true. It can be used for looking up and scanning.
 * CSS ID is assigned at cgroup allocation (create) automatically
 * and removed when subsys calls free_css_id() function. This is because
 * the lifetime of cgroup_subsys_state is subsys's matter.
 *
 * Looking up and scanning function should be called under rcu_read_lock().
 * Taking cgroup_mutex is not necessary for following calls.
 * But the css returned by this routine can be "not populated yet" or "being
 * destroyed". The caller should check css and cgroup's status.
 */

/*
 * Typically Called at ->destroy(), or somewhere the subsys frees
 * cgroup_subsys_state.
 */
void free_css_id(struct cgroup_subsys *ss, struct cgroup_subsys_state *css);

/* Find a cgroup_subsys_state which has given ID */

struct cgroup_subsys_state *css_lookup(struct cgroup_subsys *ss, int id);

/* Returns true if root is ancestor of cg */
bool css_is_ancestor(struct cgroup_subsys_state *cg,
		     const struct cgroup_subsys_state *root);

/* Get id and depth of css */
unsigned short css_id(struct cgroup_subsys_state *css);
unsigned short css_depth(struct cgroup_subsys_state *css);
struct cgroup_subsys_state *cgroup_css_from_dir(struct file *f, int id);

#else /* !CONFIG_CGROUPS */

static inline int cgroup_init_early(void) { return 0; }
static inline int cgroup_init(void) { return 0; }
static inline void cgroup_fork(struct task_struct *p) {}
static inline void cgroup_post_fork(struct task_struct *p) {}
static inline void cgroup_exit(struct task_struct *p, int callbacks) {}

static inline void cgroup_lock(void) {}
static inline void cgroup_unlock(void) {}
static inline int cgroupstats_build(struct cgroupstats *stats,
					struct dentry *dentry)
{
	return -EINVAL;
}

/* No cgroups - nothing to do */
static inline int cgroup_attach_task_all(struct task_struct *from,
					 struct task_struct *t)
{
	return 0;
}

#endif /* !CONFIG_CGROUPS */

#endif /* _LINUX_CGROUP_H */
