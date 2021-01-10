/*
 *	Berkeley style UIO structures	-	Alan Cox 1994.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI__LINUX_UIO_H
#define _UAPI__LINUX_UIO_H

#include <linux/compiler.h>
#include <linux/types.h>

//这个iovec是系统调用read/write的传输数据加强版。普通write/read是rite(int fd, const void *buf...)只能指定一个buf。
//writev/readv是writev(int fd, const struct iovec *iov, int iovcnt)，使用iovec传输多片内存中的数据，iovcnt指定iovec的个数
//每一个iovec的iov_base是用户空间buf首地址，iov_len是长度。说白了，writev可以通过iovec依次传输多片内存的数据而已，都是套路而已
struct iovec
{
	void __user *iov_base;	/* BSD uses caddr_t (1003.1g requires void *) */
	__kernel_size_t iov_len; /* Must be size_t (1003.1g) */
};

/*
 *	UIO_MAXIOV shall be at least 16 1003.1g (5.4.1.1)
 */
 
#define UIO_FASTIOV	8
#define UIO_MAXIOV	1024


#endif /* _UAPI__LINUX_UIO_H */
