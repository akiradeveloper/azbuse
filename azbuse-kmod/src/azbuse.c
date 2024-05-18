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
#include "azbuse.h"

#include <asm/uaccess.h>

static DEFINE_MUTEX(azbuse_ctl_mutex);
static DEFINE_IDR(azbuse_index_idr);

static void azbuse_flush_pending_requests(struct azbuse_device *azb)
{
	struct azb_req *req, *tmp;

	spin_lock_irq(&azb->azb_lock);
	list_for_each_entry_safe(req, tmp, &azb->azb_reqlist, list) {
		req->rq->rq_flags |= RQF_FAILED;
		blk_mq_complete_request(req->rq);
		list_del(&req->list);
	}
	spin_unlock_irq(&azb->azb_lock);
}

static int azbuse_reset(struct azbuse_device *azb)
{
	if (!azb->azb_disk->queue)
		return -EINVAL;

	azbuse_flush_pending_requests(azb);
	azb->azb_blocksize = 0;
	azb->azb_size = 0;
	invalidate_disk(azb->azb_disk);
	module_put(THIS_MODULE);
	return 0;
}

static int __azbuse_get_status(struct azbuse_device *azb, struct azbuse_info *info)
{
	memset(info, 0, sizeof(*info));
	info->azb_number = azb->azb_number;
	info->azb_size = azb->azb_size;
	info->azb_blocksize = azb->azb_blocksize;
	return 0;
}

static int azbuse_get_status(struct azbuse_device *azb, struct azbuse_info __user *arg)
{
	struct azbuse_info info;
	int err = 0;

	if (!arg)
		err = -EINVAL;
	if (!err)
		err = __azbuse_get_status(azb, &info);
	if (!err && copy_to_user(arg, &info, sizeof(info)))
		err = -EFAULT;

	return err;
}

static int __azbuse_set_status(struct azbuse_device *azb, const struct azbuse_info *info)
{
	sector_t size = (sector_t)(info->azb_size >> SECTOR_SHIFT);
	loff_t blocks;

	if (unlikely((loff_t)size != size))
		return -EFBIG;
	if (unlikely(info->azb_blocksize == 0))
		return -EINVAL;

	blocks = info->azb_size / info->azb_blocksize;
	if (unlikely(info->azb_blocksize * blocks != info->azb_size))
		return -EINVAL;

	set_disk_ro(azb->azb_disk, 0);

	set_capacity(azb->azb_disk, size);
	azb->azb_size = info->azb_size;

	blk_queue_logical_block_size(azb->azb_queue, info->azb_blocksize);
	blk_queue_physical_block_size(azb->azb_queue, info->azb_blocksize);
	azb->azb_blocksize = info->azb_blocksize;

	__module_get(THIS_MODULE);

	return 0;
}

static int azbuse_set_status(struct azbuse_device *azb, const struct azbuse_info __user *arg)
{
	struct azbuse_info info;
	if (copy_from_user(&info, arg, sizeof (struct azbuse_info)))
		return -EFAULT;
	return __azbuse_set_status(azb, &info);
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

static int azbuse_get_req(struct azbuse_device *azb, struct azbuse_xfr_hdr __user *arg)
{
	struct azbuse_xfr_hdr xfr;
	struct azb_req *req = NULL;

	if (!arg)
		return -EINVAL;
	if (!azb)
		return -ENODEV;

	if (copy_from_user(&xfr, arg, sizeof (struct azbuse_xfr_hdr)))
		return -EFAULT;

	spin_lock_irq(&azb->azb_lock);
	req = list_first_entry_or_null(&azb->azb_reqlist, struct azb_req, list);
	if (req) {
		struct req_iterator iter;
		struct bio_vec bvec;
		int i = 0;

		list_del(&req->list);
		spin_unlock_irq(&azb->azb_lock);

		// Use the pointer address as the unique id of the request
		xfr.xfr_req_id = (__u64)req;
		xfr.xfr_req_command = xfr_command_from_cmd_flags(req->rq->cmd_flags);
		xfr.xfr_io_offset = blk_rq_pos(req->rq) << SECTOR_SHIFT;
		xfr.xfr_io_len = blk_rq_bytes(req->rq);
		rq_for_each_bvec(bvec, req->rq, iter) {
			azb->azb_xfer[i].pfn = (__u64)page_to_phys(bvec.bv_page) >> PAGE_SHIFT;
			azb->azb_xfer[i].n_pages = ((bvec.bv_offset + bvec.bv_len) + (4096-1)) / 4096;
			azb->azb_xfer[i].eff_offset = bvec.bv_offset;
			azb->azb_xfer[i].eff_len = bvec.bv_len;
			i++;
		}
		xfr.xfr_vec_count = i;
		azb->azb_xfer_count = i;
	} else {
		spin_unlock_irq(&azb->azb_lock);
		return -ENOMSG;
	}

	if (copy_to_user(arg, &xfr, sizeof(xfr)))
		return -EFAULT;
	BUG_ON(xfr.xfr_transfer_address == 0);
	if (copy_to_user((__user void *) xfr.xfr_transfer_address, azb->azb_xfer, xfr.xfr_vec_count * sizeof(azb->azb_xfer[0])))
		return -EFAULT;

	return 0;
}

static struct azb_req *azbuse_find_req(struct azbuse_device *azb, __u64 id)
{
	struct azb_req *req = id;
	return req;
}

// Complete a request 
static int azbuse_put_req(struct azbuse_device *azb, struct azbuse_completion __user *arg)
{
	struct azbuse_completion cmplt;
	struct azb_req *req = NULL;

	if (!arg)
		return -EINVAL;
	if (!azb)
		return -ENODEV;

	if (copy_from_user(&cmplt, arg, sizeof (struct azbuse_completion)))
		return -EFAULT;

	req = azbuse_find_req(azb, cmplt.cmplt_req_id);
	blk_mq_end_request(req->rq, errno_to_blk_status(cmplt.cmplt_err));
	return 0;
}

static int azbuse_connect(struct file *ctl, unsigned long arg)
{
	struct file *dev;
	struct azbuse_device *azb;

	if (ctl->private_data)
		return -EBUSY;

	dev = fget(arg);
	if (!dev)
		return -EBADF;

	azb = idr_find(&azbuse_index_idr, iminor(dev->f_inode));
	fput(dev);

	if (!azb)
		return -ENODEV;

	ctl->private_data = azb;

	return 0;
}

static int azbusectl_open(struct inode *nodp, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

static int azbusectl_release(struct inode *inode, struct file *filp)
{
	struct azbuse_device *azb = filp->private_data;
	if (!azb) {
		return -ENODEV;
	}

	filp->private_data = NULL;
	return 0;
}

static unsigned int azbusectl_poll(struct file *filp, poll_table *wait)
{
	struct azbuse_device *azb = filp->private_data;
	unsigned int mask;

	if (azb == NULL)
		return -ENODEV;

	poll_wait(filp, &azb->azb_event, wait);
	mask = (list_empty(&azb->azb_reqlist)) ? 0 : POLLIN;
	return mask;
}

static int azbusectl_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct azbuse_device *azb = filp->private_data;

	int n = azb->azb_xfer_count;
	int i;
	int err_i, err = 0;
	unsigned long cur;
	
	cur = vma->vm_start;
	for (i=0; i<n; i++) {
		unsigned long pfn = azb->azb_xfer[i].pfn;
		unsigned long len = azb->azb_xfer[i].n_pages << PAGE_SHIFT;
		err = remap_pfn_range(vma, cur, pfn, len, vma->vm_page_prot);
		if (err) {
			err_i = i;
			break;
		}
		cur += len;
	}

	// Rollback on failure
	for (i=0; i<err_i; i++) {
		unsigned long pfn = azb->azb_xfer[i].pfn;
		unsigned long len = azb->azb_xfer[i].n_pages;
		unmap_mapping_pages(vma->vm_file->f_mapping, pfn, len, 0);
	}

	return err;
}

static struct block_device_operations azb_fops = {
	.owner = THIS_MODULE,
};

static int azbuse_init_request(struct blk_mq_tag_set *set, struct request *rq,
			      unsigned int hctx_idx, unsigned int numa_node)
{
	struct azb_req *req = blk_mq_rq_to_pdu(rq);

	INIT_LIST_HEAD(&req->list);
	req->rq = rq;
	return 0;
}

static blk_status_t azbuse_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	struct azb_req *req = blk_mq_rq_to_pdu(bd->rq);
	struct azbuse_device *azb = req->rq->q->queuedata;

	blk_mq_start_request(bd->rq);

	spin_lock_irq(&azb->azb_lock);
	list_add_tail(&req->list, &azb->azb_reqlist);
	spin_unlock_irq(&azb->azb_lock);

	wake_up(&azb->azb_event);
	return BLK_STS_OK;
}

static struct blk_mq_ops azbuse_mq_ops = {
	.init_request = azbuse_init_request,
	.queue_rq = azbuse_queue_rq,
};

// FIXME: error propagation
static struct azbuse_device *azbuse_add(int i)
{
	struct azbuse_device *azb;
	struct gendisk *disk;
	int err;

	azb = kzalloc(sizeof(*azb), GFP_KERNEL);
	if (!azb)
		goto out;

	if (i >= 0) {
		err = idr_alloc(&azbuse_index_idr, azb, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&azbuse_index_idr, azb, 0, 0, GFP_KERNEL);
	}
	if (err < 0)
		goto out_free_dev;
	i = err;

	azb->tag_set.ops = &azbuse_mq_ops;
	azb->tag_set.nr_hw_queues = 1;
	azb->tag_set.queue_depth = 128;
	azb->tag_set.numa_node = NUMA_NO_NODE;
	azb->tag_set.cmd_size = sizeof(struct azb_req);
	azb->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	azb->tag_set.driver_data = azb;

	err = blk_mq_alloc_tag_set(&azb->tag_set);
	if (err)
		goto out_free_idr;

	disk = blk_mq_alloc_disk(&azb->tag_set, azb);
	if (!disk)
		goto out_cleanup_tags;
	azb->azb_queue = disk->queue;
	azb->azb_queue->queuedata = azb;
	blk_queue_flag_set(QUEUE_FLAG_NONROT, azb->azb_queue);

	disk->major	= AZBUSE_MAJOR;
	disk->first_minor = i;
	disk->minors = 1;
	disk->fops = &azb_fops;
	disk->private_data = azb;
	sprintf(disk->disk_name, "azbuse%d", i);

	err = add_disk(disk);
	if (err)
		goto out_cleanup_disk;

	azb->azb_disk = disk;
	azb->azb_number = i;
	init_waitqueue_head(&azb->azb_event);
	spin_lock_init(&azb->azb_lock);
	INIT_LIST_HEAD(&azb->azb_reqlist);

	return azb;

out_cleanup_disk:
	del_gendisk(azb->azb_disk);
	put_disk(disk);
out_cleanup_tags:
	blk_mq_free_tag_set(&azb->tag_set);
out_free_idr:
	idr_remove(&azbuse_index_idr, i);
out_free_dev:
	kfree(azb);
out:
	return NULL;
}

static void azbuse_remove(struct azbuse_device *azb)
{
	del_gendisk(azb->azb_disk);
	put_disk(azb->azb_disk);
	blk_mq_free_tag_set(&azb->tag_set);
	idr_remove(&azbuse_index_idr, azb->azb_number);
	kfree(azb);
}

static long azbusectl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct azbuse_device *azb = filp->private_data;
	struct azbuse_device *remove;
	int err;

	switch (cmd) {
	case AZBUSE_GET_REQ:
		err = azbuse_get_req(azb, (struct azbuse_xfr_hdr __user *) arg);
		break;
	case AZBUSE_PUT_REQ:
		err = azbuse_put_req(azb, (struct azbuse_completion __user *) arg);
		break;
	case AZBUSE_GET_STATUS:
		mutex_lock(&azbuse_ctl_mutex);
		err = azbuse_get_status(azb, (struct azbuse_info __user *) arg);
		mutex_unlock(&azbuse_ctl_mutex);
		break;
	case AZBUSE_SET_STATUS:
		mutex_lock(&azbuse_ctl_mutex);
		err = azbuse_set_status(azb, (struct azbuse_info __user *) arg);
		mutex_unlock(&azbuse_ctl_mutex);
		break;
	case AZBUSE_RESET:
		mutex_lock(&azbuse_ctl_mutex);
		err = azbuse_reset(azb);
		mutex_unlock(&azbuse_ctl_mutex);
		break;
	case AZBUSE_CTL_ADD:
		mutex_lock(&azbuse_ctl_mutex);
		azbuse_add(arg);
		mutex_unlock(&azbuse_ctl_mutex);
		break;
	case AZBUSE_CTL_REMOVE:
		mutex_lock(&azbuse_ctl_mutex);
		remove = idr_find(&azbuse_index_idr, arg);
		if (remove == NULL) {
			err = -ENOENT;
		} else {
			err = remove->azb_number;
			azbuse_remove(remove);
		}
		mutex_unlock(&azbuse_ctl_mutex);
		break;
	case AZBUSE_CONNECT:
		mutex_lock(&azbuse_ctl_mutex);
		err = azbuse_connect(filp, arg);
		mutex_unlock(&azbuse_ctl_mutex);
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

static struct file_operations azbusectl_fops = {
	.owner = THIS_MODULE,
	.open =	azbusectl_open,
	.release = azbusectl_release,
	.unlocked_ioctl = azbusectl_ioctl,
	.poll =	azbusectl_poll,
	.mmap = azbusectl_mmap,
};

static struct miscdevice azbuse_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "azbusectl",
	.fops = &azbusectl_fops,
};

static int __init azbuse_init(void)
{
	int err;

	err = misc_register(&azbuse_misc);
	if (err < 0)
		return err;

	err = -EIO;
	if (register_blkdev(AZBUSE_MAJOR, "azbuse")) {
		printk("azbuse: register_blkdev failed!\n");
		goto unregister_misc;
	}

	printk(KERN_INFO "azbuse: module loaded\n");
	return 0;

unregister_misc:
	misc_deregister(&azbuse_misc);

	return err;
}

static int azbuse_exit_cb(int id, void *ptr, void *data)
{
	struct azbuse_device *azb = ptr;
	azbuse_remove(azb);
	return 0;
}

static void __exit azbuse_exit(void)
{
	idr_for_each(&azbuse_index_idr, azbuse_exit_cb, NULL);
	idr_destroy(&azbuse_index_idr);

	unregister_blkdev(AZBUSE_MAJOR, "azbuse");
	misc_deregister(&azbuse_misc);
}

module_init(azbuse_init);
module_exit(azbuse_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS("devname:azbusectl");
MODULE_ALIAS_BLOCKDEV_MAJOR(AZBUSE_MAJOR);