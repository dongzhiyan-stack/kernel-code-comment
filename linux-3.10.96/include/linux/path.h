#ifndef _LINUX_PATH_H
#define _LINUX_PATH_H

struct dentry;
struct vfsmount;

struct path {
    //本次搜索的文件或者目录所在的文件系统的mount结构里的vfsmount结构
	struct vfsmount *mnt;
	//就是本次搜索到的目录或者文件的dentry，在mount操作时，是挂载点目录的dentry
	struct dentry *dentry;
};

extern void path_get(const struct path *);
extern void path_put(const struct path *);

static inline int path_equal(const struct path *path1, const struct path *path2)
{
	return path1->mnt == path2->mnt && path1->dentry == path2->dentry;
}

#endif  /* _LINUX_PATH_H */
