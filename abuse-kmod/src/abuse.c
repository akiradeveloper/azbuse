/*
 * This software is a fork of
 * 
 * linux/drivers/block/abuse.c
 * Written by Zachary Amsden, 7/23/2009
 * 
 * Copyright (c) 2009 Zachary Amsden
 * Copyright (c) 2015 Naohiro Aota
 * Copyright (c) 2021 Akira Hayakawa <ruby.wktk@gmail.com>
 * 
 * Redistribution of this file is permitted under the GNU General Public License.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/buffer_head.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include "abuse.h"

#include <asm/uaccess.h>

static DEFINE_MUTEX(abuse_ctl_mutex);
static DEFINE_IDR(abuse_index_idr);

static void abuse_flush_pending_requests(struct abuse_device *ab)
{
	struct ab_req *req, *tmp;

	spin_lock_irq(&ab->ab_lock);
	list_for_each_entry_safe(req, tmp, &ab->ab_reqlist, list) {
		req->rq->rq_flags |= RQF_FAILED;
		blk_mq_complete_request(req->rq);
		list_del(&req->list);
	}
	spin_unlock_irq(&ab->ab_lock);
}

static int abuse_reset(struct abuse_device *ab)
{
	if (!ab->ab_disk->queue)
		return -EINVAL;

	abuse_flush_pending_requests(ab);
	ab->ab_blocksize = 0;
	ab->ab_size = 0;
	invalidate_disk(ab->ab_disk);
	module_put(THIS_MODULE);
	return 0;
}

static int __abuse_get_status(struct abuse_device *ab, struct abuse_info *info)
{
	memset(info, 0, sizeof(*info));
	info->ab_number = ab->ab_number;
	info->ab_size = ab->ab_size;
	info->ab_blocksize = ab->ab_blocksize;
	return 0;
}

static int abuse_get_status(struct abuse_device *ab, struct abuse_info __user *arg)
{
	struct abuse_info info;
	int err = 0;

	if (!arg)
		err = -EINVAL;
	if (!err)
		err = __abuse_get_status(ab, &info);
	if (!err && copy_to_user(arg, &info, sizeof(info)))
		err = -EFAULT;

	return err;
}

static int __abuse_set_status(struct abuse_device *ab, const struct abuse_info *info)
{
	sector_t size = (sector_t)(info->ab_size >> SECTOR_SHIFT);
	loff_t blocks;

	if (unlikely((loff_t)size != size))
		return -EFBIG;
	if (unlikely(info->ab_blocksize == 0))
		return -EINVAL;

	blocks = info->ab_size / info->ab_blocksize;
	if (unlikely(info->ab_blocksize * blocks != info->ab_size))
		return -EINVAL;

	set_disk_ro(ab->ab_disk, 0);

	set_capacity(ab->ab_disk, size);
	ab->ab_size = info->ab_size;

	blk_queue_logical_block_size(ab->ab_queue, ab->ab_blocksize);
	blk_queue_physical_block_size(ab->ab_queue, ab->ab_blocksize);
	ab->ab_blocksize = info->ab_blocksize;

	__module_get(THIS_MODULE);

	return 0;
}

static int abuse_set_status(struct abuse_device *ab, const struct abuse_info __user *arg)
{
	struct abuse_info info;
	if (copy_from_user(&info, arg, sizeof (struct abuse_info)))
		return -EFAULT;
	return __abuse_set_status(ab, &info);
}

static unsigned xfr_command_from_cmd_flags(unsigned cmd_flags) {
	unsigned int ret = 0;
	switch (cmd_flags & REQ_OP_BITS) {
		case REQ_OP_READ:
			ret = CMD_OP_READ;
			break;
		case REQ_OP_WRITE:
			ret = CMD_OP_WRITE;
			break;
		case REQ_OP_FLUSH:
			ret = CMD_OP_FLUSH;
			break;
		case REQ_OP_DISCARD:
			ret = CMD_OP_DISCARD;
			break;
		case REQ_OP_SECURE_ERASE:
			ret = CMD_OP_SECURE_ERASE;
			break;
		case REQ_OP_WRITE_ZEROES:
			ret = CMD_OP_WRITE_ZEROES;
			break;
		default:
			ret = CMD_OP_UNKNOWN;
			break;
	}
	if (cmd_flags & REQ_FUA) {
		ret |= CMD_FUA;
	}
	if (cmd_flags & REQ_PREFLUSH) {
		ret |= CMD_PREFLUSH;
	}
	if (cmd_flags & REQ_NOUNMAP) {
		ret |= CMD_NOUNMAP;
	}
	if (cmd_flags & REQ_NOWAIT) {
		ret |= CMD_NOWAIT;
	}
	if (cmd_flags & REQ_RAHEAD) {
		ret |= CMD_RAHEAD;
	}
	return ret;
}

static int abuse_get_req(struct abuse_device *ab, struct abuse_xfr_hdr __user *arg)
{
	struct abuse_xfr_hdr xfr;
	struct ab_req *req = NULL;

	if (!arg)
		return -EINVAL;
	if (!ab)
		return -ENODEV;

	if (copy_from_user(&xfr, arg, sizeof (struct abuse_xfr_hdr)))
		return -EFAULT;

	spin_lock_irq(&ab->ab_lock);
	req = list_first_entry_or_null(&ab->ab_reqlist, struct ab_req, list);
	if (req) {
		struct req_iterator iter;
		struct bio_vec bvec;
		int i = 0;

		list_move_tail(&req->list, &ab->ab_reqlist);
		spin_unlock_irq(&ab->ab_lock);

		// Use the pointer address as the unique id of the request
		xfr.ab_id = (__u64)req;
		xfr.ab_command = xfr_command_from_cmd_flags(req->rq->cmd_flags);
		xfr.ab_offset = blk_rq_pos(req->rq) << SECTOR_SHIFT;
		xfr.ab_len = blk_rq_bytes(req->rq);
		rq_for_each_segment(bvec, req->rq, iter) {
			// physical address of the page
			ab->ab_xfer[i].ab_address = (__u64)page_to_phys(bvec.bv_page);
			ab->ab_xfer[i].ab_offset = bvec.bv_offset;
			ab->ab_xfer[i].ab_len = bvec.bv_len;
			++i;
		}
		xfr.ab_vec_count = i;
	} else {
		spin_unlock_irq(&ab->ab_lock);
		return -ENOMSG;
	}

	if (copy_to_user(arg, &xfr, sizeof(xfr)))
		return -EFAULT;
	BUG_ON(xfr.ab_transfer_address == 0);
	if (copy_to_user((__user void *) xfr.ab_transfer_address, ab->ab_xfer, xfr.ab_vec_count * sizeof(ab->ab_xfer[0])))
		return -EFAULT;

	return 0;
}

static struct ab_req *abuse_find_req(struct abuse_device *ab, __u64 id)
{
	struct ab_req *req = NULL;
	list_for_each_entry(req, &ab->ab_reqlist, list) {
		if ((__u64)req == id)
			return req;
	}
	return NULL;
}

// Complete a request 
static int abuse_put_req(struct abuse_device *ab, struct abuse_completion __user *arg)
{
	struct abuse_completion xfr;
	struct ab_req *req = NULL;

	if (!arg)
		return -EINVAL;
	if (!ab)
		return -ENODEV;

	if (copy_from_user(&xfr, arg, sizeof (struct abuse_completion)))
		return -EFAULT;

	// Find the request to complete
	spin_lock_irq(&ab->ab_lock);
	req = abuse_find_req(ab, xfr.ab_id);
	if (req) {
		list_del(&req->list);
		spin_unlock_irq(&ab->ab_lock);
	} else {
		spin_unlock_irq(&ab->ab_lock);
		return -ENOMSG;
	}

	blk_mq_end_request(req->rq, errno_to_blk_status(xfr.ab_errno));
	return 0;
}

static int abuse_connect(struct file *ctl, unsigned long arg)
{
	struct file *dev;
	struct abuse_device *ab;

	if (ctl->private_data)
		return -EBUSY;

	dev = fget(arg);
	if (!dev)
		return -EBADF;

	ab = idr_find(&abuse_index_idr, iminor(dev->f_inode));
	fput(dev);

	if (!ab)
		return -ENODEV;

	ctl->private_data = ab;

	return 0;
}

static int abctl_open(struct inode *nodp, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

static int abctl_release(struct inode *inode, struct file *filp)
{
	struct abuse_device *ab = filp->private_data;
	if (!ab) {
		return -ENODEV;
	}

	filp->private_data = NULL;
	return 0;
}

static unsigned int abctl_poll(struct file *filp, poll_table *wait)
{
	struct abuse_device *ab = filp->private_data;
	unsigned int mask;

	if (ab == NULL)
		return -ENODEV;

	poll_wait(filp, &ab->ab_event, wait);
	mask = (list_empty(&ab->ab_reqlist)) ? 0 : POLLIN;
	return mask;
}

static int abctl_mmap(struct file *filp,  struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn = vma->vm_pgoff;
	return remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
}

static int ab_open(struct gendisk *disk, blk_mode_t mode)
{
	return 0;
}

static void ab_release(struct gendisk *disk)
{
	return;
}

static struct block_device_operations ab_fops = {
	.owner = THIS_MODULE,
	.open =	ab_open,
	.release = ab_release,
};

static int abuse_init_request(struct blk_mq_tag_set *set, struct request *rq,
			      unsigned int hctx_idx, unsigned int numa_node)
{
	printk("init request");
	
	struct ab_req *req = blk_mq_rq_to_pdu(rq);

	INIT_LIST_HEAD(&req->list);
	req->rq = rq;
	return 0;
}

static blk_status_t abuse_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	printk("queue request");

	struct ab_req *req = blk_mq_rq_to_pdu(bd->rq);
	struct abuse_device *ab = req->rq->q->queuedata;

	blk_mq_start_request(bd->rq);

	spin_lock_irq(&ab->ab_lock);
	list_add_tail(&req->list, &ab->ab_reqlist);
	spin_unlock_irq(&ab->ab_lock);

	wake_up(&ab->ab_event);
	return BLK_STS_OK;
}

static struct blk_mq_ops abuse_mq_ops = {
	.init_request = abuse_init_request,
	.queue_rq = abuse_queue_rq,
};

// FIXME: error propagation
static struct abuse_device *abuse_add(int i)
{
	struct abuse_device *ab;
	struct gendisk *disk;
	int err;

	ab = kzalloc(sizeof(*ab), GFP_KERNEL);
	if (!ab)
		goto out;

	if (i >= 0) {
		err = idr_alloc(&abuse_index_idr, ab, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&abuse_index_idr, ab, 0, 0, GFP_KERNEL);
	}
	if (err < 0)
		goto out_free_dev;
	i = err;

	ab->tag_set.ops = &abuse_mq_ops;
	ab->tag_set.nr_hw_queues = 1;
	ab->tag_set.queue_depth = 128;
	ab->tag_set.numa_node = NUMA_NO_NODE;
	ab->tag_set.cmd_size = sizeof(struct ab_req);
	ab->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	ab->tag_set.driver_data = ab;

	err = blk_mq_alloc_tag_set(&ab->tag_set);
	if (err)
		goto out_free_idr;

	disk = blk_mq_alloc_disk(&ab->tag_set, ab);
	if (!disk)
		goto out_cleanup_tags;
	ab->ab_queue = disk->queue;
	ab->ab_queue->queuedata = ab;
	blk_queue_flag_set(QUEUE_FLAG_NONROT, ab->ab_queue);

	disk->major	= ABUSE_MAJOR;
	disk->first_minor = i;
	disk->minors = 1;
	disk->fops = &ab_fops;
	disk->private_data = ab;
	sprintf(disk->disk_name, "abuse%d", i);

	err = add_disk(disk);
	if (err)
		goto out_cleanup_disk;

	ab->ab_disk = disk;
	ab->ab_number = i;
	init_waitqueue_head(&ab->ab_event);
	spin_lock_init(&ab->ab_lock);
	INIT_LIST_HEAD(&ab->ab_reqlist);

	return ab;

out_cleanup_disk:
	del_gendisk(ab->ab_disk);
	put_disk(disk);
out_cleanup_tags:
	blk_mq_free_tag_set(&ab->tag_set);
out_free_idr:
	idr_remove(&abuse_index_idr, i);
out_free_dev:
	kfree(ab);
out:
	return NULL;
}

static void abuse_remove(struct abuse_device *ab)
{
	del_gendisk(ab->ab_disk);
	put_disk(ab->ab_disk);
	blk_mq_free_tag_set(&ab->tag_set);
	idr_remove(&abuse_index_idr, ab->ab_number);
	kfree(ab);
}

static long abctl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct abuse_device *ab = filp->private_data;
	struct abuse_device *remove;
	int err;

	switch (cmd) {
	case ABUSE_GET_REQ:
		err = abuse_get_req(ab, (struct abuse_xfr_hdr __user *) arg);
		break;
	case ABUSE_PUT_REQ:
		err = abuse_put_req(ab, (struct abuse_completion __user *) arg);
		break;
	case ABUSE_GET_STATUS:
		mutex_lock(&abuse_ctl_mutex);
		err = abuse_get_status(ab, (struct abuse_info __user *) arg);
		mutex_unlock(&abuse_ctl_mutex);
		break;
	case ABUSE_SET_STATUS:
		mutex_lock(&abuse_ctl_mutex);
		err = abuse_set_status(ab, (struct abuse_info __user *) arg);
		mutex_unlock(&abuse_ctl_mutex);
		break;
	case ABUSE_RESET:
		mutex_lock(&abuse_ctl_mutex);
		err = abuse_reset(ab);
		mutex_unlock(&abuse_ctl_mutex);
		break;
	case ABUSE_CTL_ADD:
		mutex_lock(&abuse_ctl_mutex);
		abuse_add(arg);
		mutex_unlock(&abuse_ctl_mutex);
		break;
	case ABUSE_CTL_REMOVE:
		mutex_lock(&abuse_ctl_mutex);
		remove = idr_find(&abuse_index_idr, arg);
		if (remove == NULL) {
			err = -ENOENT;
		} else {
			err = remove->ab_number;
			abuse_remove(remove);
		}
		mutex_unlock(&abuse_ctl_mutex);
		break;
	case ABUSE_CONNECT:
		mutex_lock(&abuse_ctl_mutex);
		err = abuse_connect(filp, arg);
		mutex_unlock(&abuse_ctl_mutex);
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

static struct file_operations abctl_fops = {
	.owner = THIS_MODULE,
	.open =	abctl_open,
	.release = abctl_release,
	.unlocked_ioctl = abctl_ioctl,
	.poll =	abctl_poll,
	.mmap = abctl_mmap,
};

static struct miscdevice abuse_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "abctl",
	.fops = &abctl_fops,
};

static int __init abuse_init(void)
{
	int err;

	err = misc_register(&abuse_misc);
	if (err < 0)
		return err;

	err = -EIO;
	if (register_blkdev(ABUSE_MAJOR, "abuse")) {
		printk("abuse: register_blkdev failed!\n");
		goto unregister_misc;
	}

	printk(KERN_INFO "abuse: module loaded\n");
	return 0;

unregister_misc:
	misc_deregister(&abuse_misc);

	return err;
}

static int abuse_exit_cb(int id, void *ptr, void *data)
{
	struct abuse_device *ab = ptr;
	abuse_remove(ab);
	return 0;
}

static void __exit abuse_exit(void)
{
	idr_for_each(&abuse_index_idr, abuse_exit_cb, NULL);
	idr_destroy(&abuse_index_idr);

	unregister_blkdev(ABUSE_MAJOR, "abuse");
	misc_deregister(&abuse_misc);
}

module_init(abuse_init);
module_exit(abuse_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS("devname:abctl");
MODULE_ALIAS_BLOCKDEV_MAJOR(ABUSE_MAJOR);