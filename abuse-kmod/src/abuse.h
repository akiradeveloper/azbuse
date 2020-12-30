#ifndef _LINUX_ABUSE_H
#define _LINUX_ABUSE_H

/*
 * include/linux/abuse.h
 *
 * Copyright (c) 2009 Zachary Amsden
 * Copyright (c) 2015 Naohiro Aota
 * Copyright (c) 2021 Akira Hayakawa <ruby.wktk@gmail.com>
 * 
 * Redistribution of this file is permitted under the GNU General Public License.
 */

/*
 * Loop flags
 */
enum {
	ABUSE_FLAGS_READ_ONLY	= 1,
	ABUSE_FLAGS_RECONNECT	= 2,
};

#include <linux/types.h>	/* for __u64 */

struct abuse_info {
	__u64		   ab_device;			/* ioctl r/o */
	__u64		   ab_size;			/* ioctl r/w */
	__u32		   ab_number;			/* ioctl r/o */
	__u32		   ab_flags;			/* ioctl r/w */
	__u32		   ab_blocksize;		/* ioctl r/w */
	__u32		   ab_max_queue;		/* ioctl r/w */
	__u32		   ab_queue_size;		/* ioctl r/o */
	__u32		   ab_errors;			/* ioctl r/o */
	__u32		   ab_max_vecs;			/* ioctl r/o */
};

/*
 * IOCTL commands 
 */

#define ABUSE_GET_STATUS	0x4120
#define ABUSE_SET_STATUS	0x4121
#define ABUSE_SET_POLL		0x4122
#define ABUSE_RESET		0x4123
#define ABUSE_GET_REQ		0x4124
#define ABUSE_PUT_REQ		0x4125

#define ABUSE_CTL_ADD		0x4186
#define ABUSE_CTL_REMOVE	0x4187
#define ABUSE_CTL_GET_FREE	0x4188

#define ABUSE_ACQUIRE		0x4189
#define ABUSE_RELEASE		0x418A

struct abuse_vec {
	__u64			ab_address;
	__u32			ab_offset;
	__u32			ab_len;
};

struct abuse_xfr_hdr {
	__u64			ab_id;
	__u64			ab_offset;
	__u32			ab_command;
	__u32			ab_vec_count;
	__u64			ab_transfer_address;
};

struct abuse_completion {
	__u64 ab_id;
	__u32 ab_result;
};

/*
 * ab_commnd codes 
 */
enum {
	ABUSE_READ			= 0,
	ABUSE_WRITE			= 1,
	ABUSE_SYNC_NOTIFICATION		= 2
};

/*
 * ab_result codes 
 */
enum {
	ABUSE_RESULT_OKAY		= 0,
	ABUSE_RESULT_MEDIA_FAILURE	= 1,
	ABUSE_RESULT_DEVICE_FAILURE	= 2
};

#define ABUSE_MAJOR    60
#define ABUSECTL_MAJOR   61

#ifdef __KERNEL__
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

struct abuse_device {
	int		ab_number;
	int		ab_refcnt;
	loff_t		ab_size;
	int		ab_flags;
	int		ab_queue_size;
	int		ab_max_queue;
	int		ab_errors;

	struct block_device *ab_device;
	unsigned	ab_blocksize;

	gfp_t		old_gfp_mask;

	spinlock_t		ab_lock;
	struct list_head	ab_reqlist;
	struct mutex		ab_ctl_mutex;
	wait_queue_head_t	ab_event;

	struct request_queue	*ab_queue;
	struct blk_mq_tag_set	tag_set;
	struct gendisk		*ab_disk;

	/* user xfer area */
	struct abuse_vec	ab_xfer[BIO_MAX_PAGES];
};

struct ab_req {
	struct request		*rq;
	struct list_head	list;
};

#endif /* __KERNEL__ */

#endif
