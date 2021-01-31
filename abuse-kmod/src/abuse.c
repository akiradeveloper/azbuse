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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,16,0)
#define compat_get_disk(x) get_disk_and_module((x))
#else
#define compat_get_disk(x) get_disk((x))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define compat_queue_flag_set(x,y) blk_queue_flag_set((x),(y))
#else
#define compat_queue_flag_set(x,y) queue_flag_set_unlocked((x),(y))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#define compat_complete_request(x) blk_mq_complete_request((x))
#else
#define compat_complete_request(x) blk_complete_request((x))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#define compat_spin_lock_irqsave(x,y) spin_lock_irqsave(&(x),(y))
#define compat_spin_unlock_irqrestore(x,y) spin_unlock_irqrestore(&(x),(y))
#else
#define compat_spin_lock_irqsave(x,y) spin_lock_irqsave((x),(y))
#define compat_spin_unlock_irqrestore(x,y) spin_unlock_irqrestore((x),(y))
#endif

static DEFINE_MUTEX(abuse_devices_mutex);
// not used
// static DEFINE_MUTEX(abctl_mutex);
static DEFINE_IDR(abuse_index_idr);
static struct class *abuse_class;
static int max_part;
static int num_minors;
static int dev_shift;

static struct abuse_device *abuse_alloc(int i);
static void abuse_del_one(struct abuse_device *ab);

static void abuse_flush_pending_requests(struct abuse_device *ab)
{
	struct ab_req *req, *tmp;

	spin_lock_irq(&ab->ab_lock);
	list_for_each_entry_safe(req, tmp, &ab->ab_reqlist, list) {
		req->rq->rq_flags |= RQF_FAILED;
		compat_complete_request(req->rq);
		list_del(&req->list);
	}
	spin_unlock_irq(&ab->ab_lock);
}
static inline int is_abuse_device(struct file *file)
{
	struct inode *i = file->f_mapping->host;
	return i && S_ISBLK(i->i_mode) && MAJOR(i->i_rdev) == ABUSE_MAJOR;
}

static int reread_partition(struct block_device *bdev) {
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	int res;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	res = blkdev_ioctl(bdev, 0, BLKRRPART, 0);
	set_fs(old_fs);
	return res;
	#else
	return ioctl_by_bdev(bdev, BLKRRPART, 0);
	#endif
}

static int abuse_reset(struct abuse_device *ab)
{
	if (!ab->ab_disk->queue)
		return -EINVAL;

	abuse_flush_pending_requests(ab);
	ab->ab_flags = 0;
	ab->ab_errors = 0;
	ab->ab_blocksize = 0;
	ab->ab_size = 0;
	ab->ab_max_queue = 0;
	set_capacity(ab->ab_disk, 0);
	if (ab->ab_device) {
		// https://lkml.org/lkml/2020/8/21/268
		// should use bd_set_nr_sectors
		bd_set_size(ab->ab_device, 0);
		// Invalidate clean unused buffers and pagecache.
		invalidate_bdev(ab->ab_device);
		if (max_part > 0)
			reread_partition(ab->ab_device);
		blkdev_put(ab->ab_device, FMODE_READ);
		ab->ab_device = NULL;
		module_put(THIS_MODULE);
	}
	return 0;
}

static int abuse_set_status_int(struct abuse_device *ab, struct block_device *bdev, const struct abuse_info *info)
{
	int err;

	sector_t size = (sector_t)(info->ab_size >> SECTOR_SHIFT);
	loff_t blocks;

	if (unlikely((loff_t)size != size))
		return -EFBIG;
	if (unlikely(info->ab_blocksize == 0))
		return -EINVAL;

	blocks = info->ab_size / info->ab_blocksize;
	if (unlikely(info->ab_blocksize * blocks != info->ab_size))
		return -EINVAL;

	// This unlikely happens when ABUSE_SET_STATUS ioctl is called twice.
	// But this is unusual.
	if (unlikely(bdev)) {
		if (bdev != ab->ab_device)
			return -EBUSY;
		if (!(ab->ab_flags & ABUSE_FLAGS_RECONNECT))
			return -EINVAL;

		/*
		 * Don't allow these to change on a reconnect.
		 * We do allow changing the max queue size and
		 * the RO flag.
		 */
		if (ab->ab_size != info->ab_size ||
		    ab->ab_blocksize != info->ab_blocksize ||
		    info->ab_max_queue > ab->ab_queue_size)
		    	return -EINVAL;
	} else {
		// Acquire the block_device from ab_disk (:: gen_disk)
		bdev = bdget_disk(ab->ab_disk, 0);
		if (IS_ERR(bdev)) {
			err = PTR_ERR(bdev);
			return err;
		}
		err = blkdev_get(bdev, FMODE_READ, NULL);
		if (err) {
			bdput(bdev);
			return err;
		}
		__module_get(THIS_MODULE);
	}

	ab->ab_device = bdev;
	ab->ab_queue->queuedata = ab;
	compat_queue_flag_set(QUEUE_FLAG_NONROT, ab->ab_queue);

	ab->ab_size = info->ab_size;
	ab->ab_flags = (info->ab_flags & ABUSE_FLAGS_READ_ONLY);
	ab->ab_blocksize = info->ab_blocksize;
	ab->ab_max_queue = info->ab_max_queue;

	set_capacity(ab->ab_disk, size);
	set_device_ro(bdev, (ab->ab_flags & ABUSE_FLAGS_READ_ONLY) != 0);
	set_capacity(ab->ab_disk, size);
	bd_set_size(bdev, size << SECTOR_SHIFT);
	set_blocksize(bdev, ab->ab_blocksize);
	if (max_part > 0)
		reread_partition(bdev);

	return 0;
}

static int
abuse_set_status(struct abuse_device *ab, struct block_device *bdev, const struct abuse_info __user *arg)
{
	struct abuse_info info;
	if (copy_from_user(&info, arg, sizeof (struct abuse_info)))
		return -EFAULT;
	return abuse_set_status_int(ab, bdev, &info);
}

static int
abuse_get_status_int(struct abuse_device *ab, struct abuse_info *info)
{
	memset(info, 0, sizeof(*info));
	info->ab_size = ab->ab_size;
	info->ab_number = ab->ab_number;
	info->ab_flags = ab->ab_flags;
	info->ab_blocksize = ab->ab_blocksize;
	info->ab_max_queue = ab->ab_max_queue;
	info->ab_queue_size = ab->ab_queue_size;
	info->ab_errors = ab->ab_errors;
	info->ab_max_vecs = BIO_MAX_PAGES;
	return 0;
}

static int
abuse_get_status(struct abuse_device *ab, struct block_device *bdev, struct abuse_info __user *arg)
{
	struct abuse_info info;
	int err = 0;

	if (!arg)
		err = -EINVAL;
	if (!err)
		err = abuse_get_status_int(ab, &info);
	if (!err && copy_to_user(arg, &info, sizeof(info)))
		err = -EFAULT;

	return err;
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
		case REQ_OP_WRITE_SAME:
			ret = CMD_OP_WRITE_SAME;
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
		int i;

		list_move_tail(&req->list, &ab->ab_reqlist);
		spin_unlock_irq(&ab->ab_lock);

		// Use the pointer address as the unique id of the request
		xfr.ab_id = (__u64)req;
		xfr.ab_command = xfr_command_from_cmd_flags(req->rq->cmd_flags);
		xfr.ab_offset = blk_rq_pos(req->rq) << SECTOR_SHIFT;
		xfr.ab_len = blk_rq_bytes(req->rq);
		xfr.ab_vec_count = 0;
		ab->ab_xfer_cnt = 0;
		xfr.n_pages = 0;
		rq_for_each_segment(bvec, req->rq, iter) {
			// physical address of the page
			ab->ab_xfer[i].ab_address = (__u64)page_to_phys(bvec.bv_page);
			ab->ab_xfer[i].ab_offset = bvec.bv_offset;
			ab->ab_xfer[i].ab_len = bvec.bv_len;
			ab->ab_xfer[i].n_pages = ((bvec.bv_offset + bvec.bv_len) + (4096-1)) / 4096;

			xfr.ab_vec_count++;
			ab->ab_xfer_cnt++;
			xfr.n_pages += ab->ab_xfer[i].n_pages;

			i++;
		}
	} else {
		spin_unlock_irq(&ab->ab_lock);
		return -ENOMSG;
	}

	if (copy_to_user(arg, &xfr, sizeof(xfr)))
		return -EFAULT;
	BUG_ON(xfr.ab_transfer_address == 0);
	if (copy_to_user((__user void *)xfr.ab_transfer_address, ab->ab_xfer, xfr.ab_vec_count * sizeof(ab->ab_xfer[0])))
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

static inline void abuse_add_req(struct abuse_device *ab, struct ab_req *req)
{
	spin_lock_irq(&ab->ab_lock);
	list_add_tail(&req->list, &ab->ab_reqlist);
	spin_unlock_irq(&ab->ab_lock);
}

static int abuse_put_req(struct abuse_device *ab, struct abuse_completion __user *arg)
{
	struct abuse_completion xfr;
	struct ab_req *req = NULL;
	unsigned long flags;

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

	compat_spin_lock_irqsave(req->rq->q->queue_lock, flags);
	blk_mq_end_request(req->rq, errno_to_blk_status(xfr.ab_errno));
	compat_spin_unlock_irqrestore(req->rq->q->queue_lock, flags);

	return 0;
}

static int abuse_acquire(struct file *ctl, unsigned long arg)
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

static int abuse_release(struct file *filp)
{
	struct abuse_device *ab = filp->private_data;

	if (ab == NULL)
		return -ENODEV;

	filp->private_data = NULL;

	return 0;
}

static long abctl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct abuse_device *ab = filp->private_data;
	struct abuse_device *new, *remove;
	int err;

	// ioctl types before ABUSE_CTL_ADD (including GET_REQ, SET_REQ)
	// are executed sequentially with mutex held.
	if (cmd < ABUSE_CTL_ADD) {
		if (ab == NULL)
			return -EINVAL;
		mutex_lock(&ab->ab_ctl_mutex);
	}

	switch (cmd) {
	case ABUSE_GET_STATUS:
		err = abuse_get_status(ab, ab->ab_device, (struct abuse_info __user *) arg);
		break;
	case ABUSE_SET_STATUS:
		err = abuse_set_status(ab, ab->ab_device, (struct abuse_info __user *) arg);
		break;
	case ABUSE_RESET:
		err = abuse_reset(ab);
		break;
	case ABUSE_GET_REQ:
		err = abuse_get_req(ab, (struct abuse_xfr_hdr __user *) arg);
		break;
	case ABUSE_PUT_REQ:
		err = abuse_put_req(ab, (struct abuse_completion __user *) arg);
		break;
	case ABUSE_CTL_ADD:
		mutex_lock(&abuse_devices_mutex);
		new = abuse_alloc(arg);
		if (new) {
			add_disk(new->ab_disk);
			err = new->ab_number;
		} else {
			// FIXME: better error handling
			err = -EEXIST;
		}
		mutex_unlock(&abuse_devices_mutex);
		break;
	case ABUSE_CTL_REMOVE:
		mutex_lock(&abuse_devices_mutex);
		remove = idr_find(&abuse_index_idr, arg);
		if (remove == NULL) {
			err = -ENOENT;
		} else {
			err = remove->ab_number;
			abuse_del_one(remove);
		}
		mutex_unlock(&abuse_devices_mutex);
		break;
	case ABUSE_ACQUIRE:
		err = abuse_acquire(filp, arg);
		break;
	case ABUSE_RELEASE:
		err = abuse_release(filp);
		break;
	default:
		err = -EINVAL;
	}

	if (cmd < ABUSE_CTL_ADD) {
		mutex_unlock(&ab->ab_ctl_mutex);
	}

	return err;
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

static int abctl_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct abuse_device *ab = filp->private_data;
	int n = ab->ab_xfer_cnt;
	unsigned long cur = vma->vm_start;
	int err =0;
	int i;
	for (i=0; i<n; i++) {
		unsigned long size = ab->ab_xfer[i].n_pages << 9;
		unsigned long pfn = ab->ab_xfer[i].ab_address >> 9;
		err |= remap_pfn_range(vma, cur, pfn, size, vma->vm_page_prot);
		cur += size;
	}
	return err;
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

static int ab_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void ab_release(struct gendisk *disk, fmode_t mode)
{
	return;
}

static int abctl_open(struct inode *nodp, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

static struct block_device_operations ab_fops = {
	.owner =	THIS_MODULE,
	.open =	ab_open,
	.release =	ab_release,
};

static struct file_operations abctl_fops = {
	.owner =		THIS_MODULE,
	.open =		abctl_open,
	.release =		abctl_release,
	.unlocked_ioctl =	abctl_ioctl,
	.poll =		abctl_poll,
	.mmap = abctl_mmap,
};

static struct miscdevice abuse_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "abctl",
	.fops = &abctl_fops,
};

MODULE_ALIAS("devname:abctl");

static int max_abuse;
module_param(max_abuse, int, 0);
MODULE_PARM_DESC(max_abuse, "Maximum number of abuse devices");
module_param(max_part, int, 0);
MODULE_PARM_DESC(max_part, "Maximum number of partitions per abuse device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(ABUSE_MAJOR);

static int abuse_init_request(struct blk_mq_tag_set *set, struct request *rq,
			      unsigned int hctx_idx, unsigned int numa_node)
{
	struct ab_req *req = blk_mq_rq_to_pdu(rq);

	INIT_LIST_HEAD(&req->list);
	req->rq = rq;
	return 0;
}

static blk_status_t abuse_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	struct ab_req *req = blk_mq_rq_to_pdu(bd->rq);
	struct abuse_device *ab = req->rq->q->queuedata;

	blk_mq_start_request(bd->rq);

	spin_lock_irq(&ab->ab_lock);
	list_add_tail(&req->list, &ab->ab_reqlist);
	wake_up(&ab->ab_event);
	spin_unlock_irq(&ab->ab_lock);

	return BLK_STS_OK;
}

static struct blk_mq_ops abuse_mq_ops = {
	.queue_rq       = abuse_queue_rq,
	.init_request	= abuse_init_request,
};

// FIXME: error propagation
static struct abuse_device *abuse_alloc(int i)
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
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
	ab->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	#else
	ab->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_SG_MERGE;
	#endif
	ab->tag_set.driver_data = ab;

	err = blk_mq_alloc_tag_set(&ab->tag_set);
	if (err)
		goto out_free_idr;

	ab->ab_queue = blk_mq_init_queue(&ab->tag_set);
	if (IS_ERR_OR_NULL(ab->ab_queue))
		goto out_cleanup_tags;
	ab->ab_queue->queuedata = ab;

	disk = ab->ab_disk = alloc_disk(num_minors);
	if (!disk)
		goto out_free_queue;
	disk->major		= ABUSE_MAJOR;
	disk->first_minor	= i << dev_shift;
	disk->fops		= &ab_fops;
	disk->private_data	= ab;
	disk->queue		= ab->ab_queue;
	sprintf(disk->disk_name, "abuse%d", i);

	mutex_init(&ab->ab_ctl_mutex);
	ab->ab_number		= i;
	init_waitqueue_head(&ab->ab_event);
	spin_lock_init(&ab->ab_lock);
	INIT_LIST_HEAD(&ab->ab_reqlist);

	return ab;

out_free_queue:
	blk_cleanup_queue(ab->ab_queue);
out_cleanup_tags:
	blk_mq_free_tag_set(&ab->tag_set);
out_free_idr:
	idr_remove(&abuse_index_idr, i);
out_free_dev:
	kfree(ab);
out:
	return NULL;
}

static struct abuse_device *abuse_add_one(int i)
{
	struct abuse_device *ab;

	ab = idr_find(&abuse_index_idr, i);
	if (ab)
		return ab;

	ab = abuse_alloc(i);
	if (ab)
		add_disk(ab->ab_disk);

	return ab;
}

static struct kobject *abuse_probe(dev_t dev, int *part, void *data)
{
	struct abuse_device *ab;
	struct kobject *kobj;

	mutex_lock(&abuse_devices_mutex);
	ab = abuse_add_one(dev & MINORMASK);
	kobj = ab ? compat_get_disk(ab->ab_disk) : ERR_PTR(-ENOMEM);
	mutex_unlock(&abuse_devices_mutex);

	*part = 0;
	return kobj;
}

static void abuse_free(struct abuse_device *ab)
{
	blk_cleanup_queue(ab->ab_queue);
	blk_mq_free_tag_set(&ab->tag_set);
	idr_remove(&abuse_index_idr, ab->ab_number);
	kfree(ab);
}

static void abuse_del_one(struct abuse_device *ab)
{
	del_gendisk(ab->ab_disk);
	put_disk(ab->ab_disk);
	abuse_free(ab);
}

static int abuse_exit_cb(int id, void *ptr, void *data)
{
	struct abuse_device *ab = ptr;
	abuse_del_one(ab);
	return 0;
}

static int __init abuse_init(void)
{
	int i, nr, err;
	unsigned long range;
	struct abuse_device *ab;

	/*
	 * abuse module has a feature to instantiate underlying device
	 * structure on-demand, provided that there is an access dev node.
	 *
	 * (1) if max_abuse is specified, create that many upfront, and this
	 *     also becomes a hard limit.  Cross it and divorce is likely.
	 * (2) if max_abuse is not specified, create 8 abuse device on module
	 *     load, user can further extend abuse device by create dev node
	 *     themselves and have kernel automatically instantiate actual
	 *     device on-demand.
	 */

	dev_shift = 0;
	if (max_part > 0)
		dev_shift = fls(max_part);
	num_minors = 1 << dev_shift;

	if (max_abuse > 1UL << (MINORBITS - dev_shift))
		return -EINVAL;

	if (max_abuse) {
		nr = max_abuse;
		range = max_abuse;
	} else {
		nr = 8;
		range = 1UL << (MINORBITS - dev_shift);
	}

	err = misc_register(&abuse_misc);
	if (err < 0)
		return err;

	err = -EIO;
	if (register_blkdev(ABUSE_MAJOR, "abuse")) {
		printk("abuse: register_blkdev failed!\n");
		goto unregister_misc;
	}

	err = register_chrdev_region(MKDEV(ABUSECTL_MAJOR, 0), range, "abuse");
	if (err) {
		printk("abuse: register_chrdev_region failed!\n");
		goto unregister_blk;
	}

	abuse_class = class_create(THIS_MODULE, "abuse");
	if (IS_ERR(abuse_class)) {
		err = PTR_ERR(abuse_class);
		goto unregister_chr;
	}

	err = -ENOMEM;
	for (i = 0; i < nr; i++) {
		ab = abuse_alloc(i);
		if (!ab) {
			printk(KERN_INFO "abuse: out of memory\n");
			goto free_devices;
		}
		add_disk(ab->ab_disk);
	}

	blk_register_region(MKDEV(ABUSE_MAJOR, 0), range, THIS_MODULE, abuse_probe, NULL, NULL);

	printk(KERN_INFO "abuse: module loaded\n");
	return 0;

free_devices:
	idr_for_each(&abuse_index_idr, abuse_exit_cb, NULL);
unregister_chr:
	unregister_chrdev_region(MKDEV(ABUSECTL_MAJOR, 0), range);
unregister_blk:
	unregister_blkdev(ABUSE_MAJOR, "abuse");
unregister_misc:
	misc_deregister(&abuse_misc);
	return err;
}

static void __exit abuse_exit(void)
{
	unsigned long range;

	range = max_abuse ? max_abuse :  1UL << (MINORBITS - dev_shift);

	idr_for_each(&abuse_index_idr, abuse_exit_cb, NULL);
	idr_destroy(&abuse_index_idr);

	device_destroy(abuse_class, MKDEV(ABUSECTL_MAJOR, 0));
	class_destroy(abuse_class);

	blk_unregister_region(MKDEV(ABUSE_MAJOR, 0), range);
	unregister_chrdev_region(MKDEV(ABUSECTL_MAJOR, 0), range);
	unregister_blkdev(ABUSE_MAJOR, "abuse");
	misc_deregister(&abuse_misc);
}

module_init(abuse_init);
module_exit(abuse_exit);

#ifndef MODULE
static int __init max_abuse_setup(char *str)
{
	max_abuse = simple_strtol(str, NULL, 0);
	return 1;
}

__setup("max_abuse=", max_abuse_setup);
#endif