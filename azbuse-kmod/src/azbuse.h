/*
 * include/linux/abuse.h
 *
 * Copyright (c) 2009 Zachary Amsden
 * Copyright (c) 2015 Naohiro Aota
 * Copyright (c) 2021 Akira Hayakawa <ruby.wktk@gmail.com>
 * 
 * Redistribution of this file is permitted under the GNU General Public License.
 */

#ifndef _LINUX_AZBUSE_H
#define _LINUX_AZBUSE_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/types.h> /* for __u64 */

struct azbuse_info {
	__u32 azb_number; /* r/o */
	__u64 azb_size; /* r/w */
	__u32 azb_blocksize; /* r/w */
};

#define AZBUSE_GET_STATUS 0x4120
#define AZBUSE_SET_STATUS 0x4121
#define AZBUSE_RESET	0x4122
#define AZBUSE_GET_REQ 0x4123
#define AZBUSE_PUT_REQ 0x4124

#define AZBUSE_CTL_ADD 0x4186
#define AZBUSE_CTL_REMOVE 0x4187
#define AZBUSE_CONNECT 0x4188

#define CMD_OP_UNKNOWN 0
#define CMD_OP_READ 1
#define CMD_OP_WRITE 2
#define CMD_OP_FLUSH 3
#define CMD_OP_DISCARD 4
#define CMD_OP_SECURE_ERASE 5
#define CMD_OP_WRITE_ZEROES 6

#define CMD_FUA 1<<8
#define CMD_PREFLUSH 1<<9
#define CMD_NOUNMAP 1<<10
#define CMD_NOWAIT 1<<11
#define CMD_RAHEAD 1<<12

struct azbuse_xfr_hdr {
	__u64 xfr_req_id;
	__u32 xfr_req_command;
	__u64 xfr_io_offset;
	__u64 xfr_io_len;
	__u32 xfr_vec_count;
	__u64 xfr_transfer_address;
	__u8 page_shift;
};

struct azbuse_vec {
	__u64 pfn;
	__u32 n_pages;
	__u32 eff_offset;
	__u32 eff_len;
};

struct azbuse_completion {
	__u64 cmplt_req_id;
	__s32 cmplt_err;
};

#define AZBUSE_MAJOR 60
#define AZBUSECTL_MAJOR 61

struct azbuse_device {
	int azb_number;
	loff_t azb_size;
	unsigned azb_blocksize;

	spinlock_t azb_lock;
	struct list_head azb_reqlist;
	wait_queue_head_t azb_event;

	struct request_queue *azb_queue;
	struct blk_mq_tag_set tag_set;
	struct gendisk *azb_disk;

	/* user xfer area */
	int azb_xfer_count;
	struct azbuse_vec azb_xfer[BIO_MAX_VECS];
};

struct azb_req {
	struct request *rq;
	struct list_head list;
};

#endif