/******************************************************************************
*
* Copyright (C) 2026 Allegro DVT.  All rights reserved.
*
******************************************************************************/

#include <linux/delay.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "al_codec_mb.h"
#include "al_codec_msg.h"
#include "al_common.h"
#include "al_dmabuf.h"
#include "al_riscv_drv.h"

#include "msg_common_itf.h"
#include "codec_uapi.h"

#define codec_dbg(dev, fmt, ...) \
	dev_dbg(&dev->common.pdev->dev, fmt, ##__VA_ARGS__)
#define codec_info(dev, fmt, ...) \
	dev_info(&dev->common.pdev->dev, fmt, ##__VA_ARGS__)
#define codec_warn(dev, fmt, ...) \
	dev_warn(&dev->common.pdev->dev, fmt, ##__VA_ARGS__)
#define codec_err(dev, fmt, ...) \
	dev_err(&dev->common.pdev->dev, fmt, ##__VA_ARGS__)

struct device_data {
	const char *fw_name;
	const char *default_device_name;
};

struct codec_cmd {
	struct kref refcount;
	struct list_head list;
	struct completion done;
	int reply_size;
	void *reply;
};

struct codec_event_wrapper {
	struct list_head list;
	uint32_t type;
	uint32_t payload_len;
	char payload[];
};

static bool map_in_kernel = 0;
module_param(map_in_kernel, bool, S_IRUGO);

#define MSG_ITF_TYPE_LIMIT BIT(10)

static inline bool is_type_reply(u16 type)
{
	return type >= MSG_ITF_TYPE_FIRST_REPLY &&
	       type < MSG_ITF_TYPE_FIRST_REPLY + MSG_ITF_TYPE_LIMIT;
}

static inline bool is_type_event(u16 type)
{
	return type >= MSG_ITF_TYPE_FIRST_EVT &&
	       type < MSG_ITF_TYPE_FIRST_EVT + MSG_ITF_TYPE_LIMIT;
}

static inline struct al_dma_buf *client_dma_buf_lookup(struct codec_client *ctx,
						       dma_addr_t buf_paddr)
{
	struct al_dma_buf *buf;
	struct al_dma_buf *res = NULL;

	mutex_lock(&ctx->dma_lock);
	list_for_each_entry(buf, &ctx->dma_buffers, list) {
		if (likely(buf->dma_handle == buf_paddr)) {
			res = buf;
			break;
		}
	}
	mutex_unlock(&ctx->dma_lock);

	return res;
}

static int client_create_and_insert(struct codec_dev *dev, struct file *file)
{
	struct codec_client *client;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client) {
		codec_err(dev, "Unable to alloc memory\n");
		return -ENOMEM;
	}

	kref_init(&client->refcount);
	client->dev = dev;
	client->file = file;
	mutex_init(&client->event_lock);
	mutex_init(&client->client_lock);
	mutex_init(&client->dma_lock);
	INIT_LIST_HEAD(&client->events);
	INIT_LIST_HEAD(&client->cmds);
	INIT_LIST_HEAD(&client->dma_buffers);
	init_waitqueue_head(&client->event_queue);

	mutex_lock(&dev->client_lock);
	list_add(&client->list, &dev->clients);
	mutex_unlock(&dev->client_lock);

	codec_info(dev, "New client %p for %p\n", client, file);

	return 0;
}

static inline void client_cleanup_event_list(struct list_head *events)
{
	struct codec_event_wrapper *next;
	struct codec_event_wrapper *evt;

	list_for_each_entry_safe(evt, next, events, list) {
		list_del(&evt->list);
		kfree(evt);
	}
}

static inline void client_dma_buf_cleanup(struct codec_client *ctx)
{
	struct al_dma_buf *buf, *next;
	struct codec_dev *dev = ctx->dev;

	mutex_lock(&ctx->dma_lock);

	list_for_each_entry_safe(buf, next, &ctx->dma_buffers, list) {
		common_dma_free(&dev->common, buf->size, buf->cpu_mem,
				buf->dma_handle);
		list_del(&buf->list);
		kfree(buf);
	}

	mutex_unlock(&ctx->dma_lock);
}

static void client_cleanup(struct kref *ref)
{
	struct codec_client *client =
		container_of(ref, struct codec_client, refcount);
	struct codec_dev *dev = client->dev;

	if (!list_empty(&client->cmds))
		codec_err(dev, "cmds list not empty\n");

	client_cleanup_event_list(&client->events);
	client_dma_buf_cleanup(client);

	kfree(client);
}

static struct codec_client *client_lookup(struct codec_dev *dev,
					  struct file *file)
{
	struct codec_client *ctx;
	struct codec_client *res = NULL;

	mutex_lock(&dev->client_lock);
	list_for_each_entry(ctx, &dev->clients, list) {
		if (likely(ctx->file == file)) {
			res = ctx;
			break;
		}
	}
	mutex_unlock(&dev->client_lock);

	return res;
}

void client_dma_buf_insert(struct codec_client *ctx, struct al_dma_buf *buf)
{
	mutex_lock(&ctx->dma_lock);
	list_add(&buf->list, &ctx->dma_buffers);
	mutex_unlock(&ctx->dma_lock);
}

void client_dma_buf_remove(struct codec_client *ctx, struct al_dma_buf *buf)
{
	mutex_lock(&ctx->dma_lock);
	list_del(&buf->list);
	mutex_unlock(&ctx->dma_lock);
}

static struct codec_client *client_get(struct codec_dev *dev, uint64_t hdl)
{
	struct codec_client *res = NULL;
	struct codec_client *client;

	mutex_lock(&dev->client_lock);
	list_for_each_entry(client, &dev->clients, list) {
		if (client == al_phys_to_virt(hdl)) {
			res = client;
			kref_get(&client->refcount);
			break;
		}
	}
	mutex_unlock(&dev->client_lock);

	return res;
}

static void client_put(struct codec_client *client)
{
	kref_put(&client->refcount, client_cleanup);
}

static inline void client_notify_fw(struct codec_dev *dev,
				    struct codec_client *client)
{
	struct msg_itf_header hdr;
	int ret;

	hdr.type = MSG_ITF_TYPE_CLIENT_LEAVE;
	hdr.driver_client_handle = al_virt_to_phys(client);
	hdr.driver_command_handle = 0;
	hdr.payload_len = 0;

	ret = al_common_send(&dev->common, &hdr);
	if (ret)
		codec_info(dev, "Unable to notify fw that client %p leaved\n",
			   client);
}

static void client_remove(struct codec_dev *dev, struct codec_client *client)
{
	codec_info(dev, "Remove client %p for %p\n", client, client->file);

	mutex_lock(&dev->client_lock);
	list_del(&client->list);
	mutex_unlock(&dev->client_lock);

	client_notify_fw(dev, client);

	client_put(client);
}

static void cmd_cleanup(struct kref *ref)
{
	struct codec_cmd *cmd = container_of(ref, struct codec_cmd, refcount);

	kfree(cmd->reply);
	kfree(cmd);
}

static struct codec_cmd *
cmd_create_and_insert(struct codec_client *client,
		      struct codec_cmd_reply *cmd_reply)
{
	struct codec_cmd *cmd;

	cmd = kmalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return NULL;

	cmd->reply = kmalloc(cmd_reply->reply_size, GFP_KERNEL);
	if (!cmd->reply) {
		kfree(cmd);
		return NULL;
	}

	kref_init(&cmd->refcount);
	cmd->reply_size = cmd_reply->reply_size;
	init_completion(&cmd->done);

	mutex_lock(&client->client_lock);
	list_add(&cmd->list, &client->cmds);
	mutex_unlock(&client->client_lock);

	return cmd;
}

static struct codec_cmd *cmd_get(struct codec_client *client, uint64_t hdl)
{
	struct codec_cmd *cmd;
	struct codec_cmd *res = NULL;

	mutex_lock(&client->client_lock);
	list_for_each_entry(cmd, &client->cmds, list) {
		if (cmd == al_phys_to_virt(hdl)) {
			res = cmd;
			kref_get(&cmd->refcount);
			break;
		}
	}
	mutex_unlock(&client->client_lock);

	return res;
}

static void cmd_put(struct codec_cmd *cmd)
{
	kref_put(&cmd->refcount, cmd_cleanup);
}

static void cmd_remove(struct codec_client *client, struct codec_cmd *cmd)
{
	mutex_lock(&client->client_lock);
	list_del(&cmd->list);
	mutex_unlock(&client->client_lock);

	cmd_put(cmd);
}

static int codec_open(struct inode *inode, struct file *file)
{
	struct codec_dev *dev =
		container_of(file->private_data, struct codec_dev, misc);

	return client_create_and_insert(dev, file);
}

static int codec_release(struct inode *inode, struct file *file)
{
	struct codec_dev *dev =
		container_of(file->private_data, struct codec_dev, misc);
	struct codec_client *client;

	client = client_lookup(dev, file);
	if (!client)
		codec_warn(dev, "client not found for %p\n", file);
	else
		client_remove(dev, client);

	return 0;
}

static int codec_ioctl_cmd_reply(struct codec_dev *dev, unsigned long arg,
				 struct codec_client *client)
{
	void __user *ubuf = (void __user *)arg;
	struct msg_itf_header *req = NULL;
	struct codec_cmd_reply cmd_reply;
	struct codec_cmd *cmd = NULL;
	int ret;

	if (!client)
		return -ENODEV;

	if (copy_from_user(&cmd_reply, ubuf, sizeof(cmd_reply)))
		return -EFAULT;

	req = kzalloc(cmd_reply.req_size, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	if (copy_from_user(req, cmd_reply.req, cmd_reply.req_size)) {
		ret = -EFAULT;
		goto free_req;
	}

	cmd = cmd_create_and_insert(client, &cmd_reply);
	if (!cmd) {
		ret = -ENOMEM;
		goto free_req;
	}

	req->driver_client_handle = al_virt_to_phys(client);
	req->driver_command_handle = al_virt_to_phys(cmd);
	ret = al_common_send(&dev->common, req);
	if (ret)
		goto remove_cmd;

	ret = wait_for_completion_killable(&cmd->done);
	if (ret)
		goto remove_cmd;

	if (copy_to_user(cmd_reply.reply, cmd->reply, cmd_reply.reply_size)) {
		ret = -EFAULT;
		goto remove_cmd;
	}

	ret = 0;

remove_cmd:
	cmd_remove(client, cmd);
free_req:
	kfree(req);

	return ret;
}

static struct al_dma_buf *codec_dma_alloc(struct codec_dev *dev,
					  struct codec_dma_info *info)
{
	struct al_dma_buf *buf;

	buf = kmalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	buf->size = info->size;
	buf->is_kernel_mapped = map_in_kernel;
	buf->is_coherent = true;
	buf->dmabuf_handle = NULL;
	buf->cpu_mem = common_dma_alloc(&dev->common, info->size,
					&buf->dma_handle, GFP_KERNEL);

	if (IS_ERR(buf->cpu_mem)) {
		kfree(buf);
		return ERR_PTR(-ENOMEM);
	}

	info->phy_addr = buf->dma_handle;
	info->offset = buf->dma_handle;

	return buf;
}

static int codec_ioctl_dma_alloc(struct codec_dev *dev, unsigned long arg,
				 struct codec_client *client)
{
	void __user *ubuf = (void __user *)arg;
	struct codec_dma_info info;
	struct al_dma_buf *buf;

	if (copy_from_user(&info, ubuf, sizeof(info)))
		return -EFAULT;

	buf = codec_dma_alloc(dev, &info);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	if (copy_to_user(ubuf, &info, sizeof(info))) {
		common_dma_free(&dev->common, info.size, buf->cpu_mem,
				buf->dma_handle);
		kfree(buf);
		return -EFAULT;
	}

	client_dma_buf_insert(client, buf);

	return 0;
}

static int codec_ioctl_dma_alloc_w_fd(struct codec_dev *dev, unsigned long arg,
				      struct codec_client *client)
{
	void __user *ubuf = (void __user *)arg;
	struct codec_dma_info info;
	struct al_dma_buf *buf;
	struct dma_buf *dma_buf;

	if (copy_from_user(&info, ubuf, sizeof(info)))
		return -EFAULT;

	buf = codec_dma_alloc(dev, &info);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	dma_buf = codec_dmabuf_wrap(&dev->common.pdev->dev, info.size, buf,
				    client);

	if (IS_ERR(dma_buf)) {
		common_dma_free(&dev->common, info.size, buf->cpu_mem,
				buf->dma_handle);
		return PTR_ERR(dma_buf);
	}

	buf->dmabuf_handle = dma_buf;
	info.fd = dma_buf_fd(dma_buf, O_RDWR);

	if (copy_to_user(ubuf, &info, sizeof(info))) {
		common_dma_free(&dev->common, buf->size, buf->cpu_mem,
				buf->dma_handle);
		kfree(buf);
		return -EFAULT;
	}

	client_dma_buf_insert(client, buf);

	return 0;
}

static int codec_ioctl_dma_free(struct codec_dev *dev, unsigned long arg,
				struct codec_client *client)
{
	void __user *ubuf = (void __user *)arg;
	struct codec_dma_info info;
	struct al_dma_buf *buf;

	if (copy_from_user(&info, ubuf, sizeof(info)))
		return -EFAULT;

	buf = client_dma_buf_lookup(client, info.phy_addr);
	if (!buf)
		return -EINVAL;

	common_dma_free(&dev->common, buf->size, buf->cpu_mem, buf->dma_handle);
	list_del(&buf->list);
	kfree(buf);

	return 0;
}

/* Note that there is no race with handle_put_cma_req since mcu is not supposed
 * to deallocate this memory.
 */
static int codec_ioctl_dma_free_mcu(struct codec_dev *dev, unsigned long arg)
{
	void __user *ubuf = (void __user *)arg;
	struct codec_dma_info info;

	if (copy_from_user(&info, ubuf, sizeof(info)))
		return -EFAULT;

	return al_common_dma_buf_free(&dev->common, info.phy_addr);
}

static int codec_ioctl_fw_info(struct codec_dev *dev, unsigned long arg)
{
	void __user *ubuf = (void __user *)arg;
	struct codec_fw_info info;

	info.version = dev->common.fw_version;

	if (copy_to_user(ubuf, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static int codec_ioctl_get_event(struct codec_dev *dev, unsigned long arg,
				 struct codec_client *client)
{
	void __user *ubuf = (void __user *)arg;
	struct codec_event event;
	struct codec_event_wrapper *evt;
	int ret;

	if (copy_from_user(&event, ubuf, sizeof(event)))
		return -EFAULT;

	mutex_lock(&client->event_lock);
	while (list_empty(&client->events)) {
		mutex_unlock(&client->event_lock);
		ret = wait_event_interruptible_timeout(
			client->event_queue, !list_empty(&client->events), HZ);
		if (ret < 0)
			return ret;
		if (ret == 0)
			return -ETIMEDOUT;
		mutex_lock(&client->event_lock);
	}
	evt = list_entry(client->events.next, struct codec_event_wrapper, list);
	list_del(&evt->list);
	mutex_unlock(&client->event_lock);

	if (copy_to_user(event.event, evt->payload, evt->payload_len)) {
		kfree(evt);
		return -EFAULT;
	}
	event.type = evt->type;
	ret = (!copy_to_user(ubuf, &event, sizeof(event))) ? 0 : -EFAULT;
	kfree(evt);

	return ret;
}

static int codec_ioctl_get_physical_address(struct codec_dev *dev,
					    unsigned long arg,
					    struct codec_client *client)
{
	struct codec_dma_info info;
	struct dma_buf *dbuf;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	int err = 0;

	if (copy_from_user(&info, (struct al5_dma32_info *)arg, sizeof(info)))
		return -EFAULT;

	dbuf = dma_buf_get(info.fd);
	if (IS_ERR(dbuf))
		return -EINVAL;
	attach = dma_buf_attach(dbuf, &dev->common.pdev->dev);
	if (IS_ERR(attach)) {
		err = -EINVAL;
		goto fail_attach;
	}
	sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		err = -EINVAL;
		goto fail_map;
	}

	info.phy_addr = sg_dma_address(sgt->sgl);
	info.offset = info.phy_addr;

	dma_buf_unmap_attachment(attach, sgt, DMA_BIDIRECTIONAL);

fail_map:
	dma_buf_detach(dbuf, attach);
fail_attach:
	dma_buf_put(dbuf);

	if (err)
		return err;

	if (copy_to_user((void *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static long codec_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct codec_dev *dev =
		container_of(file->private_data, struct codec_dev, misc);
	struct codec_client *client = client_lookup(dev, file);
	int ret;

	if (!client)
		return -ENODEV;

	switch (cmd) {
	case CODEC_FW_CMD_REPLY:
		ret = codec_ioctl_cmd_reply(dev, arg, client);
		break;
	case CODEC_DMA_ALLOC:
		ret = codec_ioctl_dma_alloc(dev, arg, client);
		break;
	case CODEC_DMA_ALLOC_WITH_FD:
		ret = codec_ioctl_dma_alloc_w_fd(dev, arg, client);
		break;
	case CODEC_DMA_FREE:
		ret = codec_ioctl_dma_free(dev, arg, client);
		break;
	case CODEC_GET_EVENT:
		ret = codec_ioctl_get_event(dev, arg, client);
		break;
	case CODEC_DMA_FREE_MCU:
		ret = codec_ioctl_dma_free_mcu(dev, arg);
		break;
	case CODEC_DMA_GET_PHY:
		ret = codec_ioctl_get_physical_address(dev, arg, client);
		break;
	case CODEC_GET_FW_INFO:
		ret = codec_ioctl_fw_info(dev, arg);
		break;
	default:
		codec_err(dev, "unknown ioctl %x\n", cmd);
		codec_err(dev, "Existing ioctls:\n");
		codec_err(dev, "CODEC_FW_CMD_REPLY: %lx\n", CODEC_FW_CMD_REPLY);
		codec_err(dev, "CODEC_DMA_ALLOC: %lx\n", CODEC_DMA_ALLOC);
		codec_err(dev, "CODEC_DMA_ALLOC_WITH_FD: %lx\n",
			  CODEC_DMA_ALLOC_WITH_FD);
		codec_err(dev, "CODEC_DMA_FREE: %lx\n", CODEC_DMA_FREE);
		codec_err(dev, "CODEC_GET_EVENT: %lx\n", CODEC_GET_EVENT);
		codec_err(dev, "CODEC_DMA_FREE_MCU: %lx\n", CODEC_DMA_FREE_MCU);
		codec_err(dev, "CODEC_DMA_GET_PHY: %lx\n", CODEC_DMA_GET_PHY);
		codec_err(dev, "CODEC_GET_FW_INFO: %lx\n", CODEC_GET_FW_INFO);
		ret = -EINVAL;
	}

	return ret;
}

static int codec_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct codec_dev *dev =
		container_of(file->private_data, struct codec_dev, misc);
	struct codec_client *ctx = client_lookup(dev, file);
	size_t vm_size = vma->vm_end - vma->vm_start;
	struct al_dma_buf *buf;
	int ret;

	if (!ctx)
		return -ENODEV;

	buf = client_dma_buf_lookup(ctx, PFN_PHYS(vma->vm_pgoff));
	codec_dbg(dev, "buf lookup into driver -> %p", buf);
	if (!buf)
		return al_common_dma_buf_map(&dev->common, vma);

	vma->vm_pgoff = 0;
	ret = dma_mmap_coherent(&dev->common.pdev->dev, vma, buf->cpu_mem,
				buf->dma_handle, vm_size);

	if (ret < 0)
		return al_common_dma_buf_map(&dev->common, vma);

	return 0;
}

static const struct file_operations codec_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = codec_ioctl,
	.open = codec_open,
	.release = codec_release,
	.mmap = codec_mmap,
};

static void handle_cmd_reply(struct codec_dev *dev, struct msg_itf_header *hdr)
{
	struct codec_client *client;
	struct codec_cmd *cmd = NULL;
	int ret;

	client = client_get(dev, hdr->driver_client_handle);
	if (!client) {
		codec_dbg(dev, "Unable to find client %p for reply %d\n",
			  al_phys_to_virt(hdr->driver_client_handle),
			  hdr->type);
		goto error;
	}

	cmd = cmd_get(client, hdr->driver_command_handle);
	if (!cmd) {
		codec_dbg(dev, "Unable to find command\n");
		goto error;
	}

	if (cmd->reply_size != hdr->payload_len) {
		codec_err(dev, "mismatch size %d %d\n", cmd->reply_size,
			  hdr->payload_len);
		goto error;
	}

	ret = al_common_get_data(&dev->common, cmd->reply, hdr->payload_len);
	if (ret)
		codec_err(dev, "Unable to copy reply\n");

	complete(&cmd->done);

	cmd_put(cmd);
	client_put(client);

	return;

error:
	if (cmd)
		cmd_put(cmd);
	if (client)
		client_put(client);
	/* try to skip data to avoid fetching wrong header */
	ret = al_common_get_data(&dev->common, NULL, hdr->payload_len);
	if (ret)
		codec_err(dev, "Unable to copy reply\n");
}

static void handle_evt(struct codec_dev *dev, struct msg_itf_header *hdr,
		       int type)
{
	struct codec_event_wrapper *evt;
	struct codec_client *client;
	int ret;

	client = client_get(dev, hdr->driver_client_handle);
	if (!client) {
		codec_dbg(dev, "Unable to find client %p for evt %d\n",
			  al_phys_to_virt(hdr->driver_client_handle), type);
		goto error;
	}

	evt = kmalloc(sizeof(*evt) + hdr->payload_len, GFP_KERNEL);
	if (!evt) {
		client_put(client);
		codec_err(dev, "Unable to alloc event\n");
		goto error;
	}

	evt->payload_len = hdr->payload_len;
	evt->type = type;

	ret = al_common_get_data(&dev->common, evt->payload, hdr->payload_len);
	if (ret) {
		kfree(evt);
		client_put(client);
		codec_err(dev, "Unable to get event\n");
		return;
	}

	mutex_lock(&client->event_lock);
	list_add_tail(&evt->list, &client->events);
	mutex_unlock(&client->event_lock);
	wake_up_interruptible(&client->event_queue);

	client_put(client);

	return;

error:
	if (client)
		client_put(client);
	/* try to skip data to avoid fetching wrong header */
	ret = al_common_get_data(&dev->common, NULL, hdr->payload_len);
	if (ret)
		codec_err(dev, "Unable to copy reply\n");
}

static void codec_process_msg(void *cb_arg, struct msg_itf_header *hdr)
{
	struct codec_dev *dev = cb_arg;

	if (is_type_reply(hdr->type))
		handle_cmd_reply(dev, hdr);
	else if (is_type_event(hdr->type))
		handle_evt(dev, hdr, hdr->type);
	else {
		codec_err(dev, "Unsupported message type %d\n", hdr->type);
		/* skip data */
		al_common_get_data(&dev->common, NULL, hdr->payload_len);
	}
}

static void codec_fw_ready(void *cb_arg)
{
	struct codec_dev *dev = cb_arg;
	struct device *device = &dev->common.pdev->dev;
	struct al_riscv_match_data *data;
	const char *device_name;
	struct miscdevice *misc;
	int ret;

	data = (struct al_riscv_match_data *)of_device_get_match_data(device);
	if (!data) {
		codec_err(dev, "Unable to find device data\n");
		return;
	}

	device_name = data->default_device_name;
	of_property_read_string(device->of_node, "al,devicename", &device_name);
	snprintf(dev->misc_name, MAX_MISC_NAME, device_name);
	misc = &dev->misc;
	misc->minor = MISC_DYNAMIC_MINOR;
	misc->name = dev->misc_name;
	misc->fops = &codec_fops;
	ret = misc_register(misc);
	if (ret)
		codec_err(dev, "Unable to register misc device\n");
	else
		dev->is_misc_init_done = 1;
}

int codec_probe(struct platform_device *pdev)
{
	struct al_riscv_match_data *data;
	struct codec_dev *dev;
	int ret;

	dev_info(&pdev->dev, "Probing ...\n");

	data = (struct al_riscv_match_data *)of_device_get_match_data(
		&pdev->dev);
	if (!data) {
		dev_err(&pdev->dev, "Unable to find device data\n");
		return -EINVAL;
	}

	dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;
	mutex_init(&dev->client_lock);
	INIT_LIST_HEAD(&dev->clients);

	dev->common.cb_arg = dev;
	dev->common.process_msg_cb = codec_process_msg;
	dev->common.fw_ready_cb = codec_fw_ready;
	ret = al_common_probe(pdev, &dev->common, data->fw_name, map_in_kernel);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, dev);
	codec_info(dev, "Probing done successfully %p\n", dev);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
void codec_remove(struct platform_device *pdev)
#else
int codec_remove(struct platform_device *pdev)
#endif
{
	struct codec_dev *dev = platform_get_drvdata(pdev);

	dev_info(&pdev->dev, "remove %p\n", dev);
	if (dev->is_misc_init_done)
		misc_deregister(&dev->misc);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
	al_common_remove(&dev->common);
#else
	return al_common_remove(&dev->common);
#endif
}
