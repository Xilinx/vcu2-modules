/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include "al_dmabuf.h"

#include <linux/dma-buf.h>
#include <linux/slab.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,15,0)
MODULE_IMPORT_NS(DMA_BUF);
#endif

struct codec_dma_buf_priv {
	struct codec_dma_buf *buffer;
	
	struct codec_client *client;
	/* DMABUF related */
	struct device *dev;
	struct sg_table *sgt_base;
	enum dma_data_direction dma_dir;

};


struct codec_dma_buf_attachment {
	struct sg_table sgt;
	enum dma_data_direction dma_dir;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
/* device argument was removed */
static int codec_dmabuf_attach(struct dma_buf *dbuf, struct dma_buf_attachment *dbuf_attach)
#else
static int codec_dmabuf_attach(struct dma_buf *dbuf, struct device *dev,
			     struct dma_buf_attachment *dbuf_attach)
#endif
{
	struct codec_dma_buf_priv *dinfo = dbuf->priv;

	struct codec_dma_buf_attachment *attach;

	struct scatterlist *rd, *wr;
	struct sg_table *sgt;
	int ret, i;

	attach = kzalloc(sizeof(*attach), GFP_KERNEL);
	if (!attach)
		return -ENOMEM;

	sgt = &attach->sgt;

	ret = sg_alloc_table(sgt, dinfo->sgt_base->orig_nents, GFP_KERNEL);
	if (ret) {
		kfree(attach);
		return -ENOMEM;
	}

	rd = dinfo->sgt_base->sgl;
	wr = sgt->sgl;

	for (i = 0; i < sgt->orig_nents; ++i) {
		sg_set_page(wr, sg_page(rd), rd->length, rd->offset);
		/* map the scatter gather list. As the mapping is coherent we only add
		 * the dma address and the dma length in the scatterlist without doing
		 * the costly cache invalidation */
		sg_dma_address(wr) = dinfo->buffer->dma_handle;
		sg_dma_len(wr) = rd->length;
		rd = sg_next(rd);
		wr = sg_next(wr);
	}

	attach->dma_dir = DMA_NONE;

	dbuf_attach->priv = attach;

	return 0;
}

static void codec_dmabuf_detach(struct dma_buf *dbuf,
			      struct dma_buf_attachment *db_attach)
{
	struct codec_dma_buf_attachment *attach = db_attach->priv;
	struct sg_table *sgt;

	if (!attach)
		return;

	sgt = &attach->sgt;

	sg_free_table(sgt);
	kfree(attach);
	db_attach->priv = NULL;
}

static struct sg_table *codec_dmabuf_map(struct dma_buf_attachment *db_attach,
				       enum dma_data_direction dma_dir)
{
	struct codec_dma_buf_attachment *attach = db_attach->priv;
	struct sg_table *sgt;
	struct mutex *lock = &db_attach->dmabuf->lock;

	mutex_lock(lock);

	sgt = &attach->sgt;

	if (attach->dma_dir == dma_dir) {
		mutex_unlock(lock);
		return sgt;
	}

	if (attach->dma_dir != DMA_NONE) {
		pr_err("-> DMA-DIR NONE ");
		dma_unmap_sg_attrs(db_attach->dev, sgt->sgl, sgt->orig_nents,
				   attach->dma_dir, DMA_ATTR_SKIP_CPU_SYNC);
		attach->dma_dir = DMA_NONE;
	}

	sgt->nents = dma_map_sg_attrs(db_attach->dev, sgt->sgl, sgt->orig_nents,
				      dma_dir, DMA_ATTR_SKIP_CPU_SYNC);

	if (!sgt->nents) {
		pr_err("failed to map scatterlist\n");
		mutex_unlock(lock);
		return ERR_PTR(-EIO);
	}

	attach->dma_dir = dma_dir;

	mutex_unlock(lock);

	return sgt;
}

static void codec_dmabuf_unmap(struct dma_buf_attachment *at,
			     struct sg_table *sg, enum dma_data_direction dir)
{
}


static int codec_dmabuf_mmap(struct dma_buf *dbuf, struct vm_area_struct *vma)
{
	struct codec_dma_buf_priv *dinfo = dbuf->priv;
	unsigned long start = vma->vm_start;
	unsigned long vsize = vma->vm_end - start;
	struct codec_dma_buf *buffer = dinfo->buffer;
	int ret;

	if (!dinfo) {
		pr_err("No buffer to map\n");
		return -EINVAL;
	}

	vma->vm_pgoff = 0;

	ret = dma_mmap_coherent(dinfo->dev, vma, buffer->cpu_mem,
				buffer->dma_handle, vsize);


	if (ret < 0) {
		pr_err("Remapping memory failed, error: %d\n", ret);
		return ret;
	}

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

	return 0;
}

static void codec_dmabuf_release(struct dma_buf *dbuf)
{
	struct codec_dma_buf_priv *dinfo = dbuf->priv;
	struct codec_dma_buf *buffer = dinfo->buffer;

	if (dinfo->sgt_base) {
		sg_free_table(dinfo->sgt_base);
		kfree(dinfo->sgt_base);
	}

	client_dma_buf_remove(dinfo->client, buffer);

	buf_free_dma_coherent(dinfo->dev, buffer);


	put_device(dinfo->dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	kfree_sensitive(buffer);
#else
	kzfree(buffer);
#endif
	kfree(dinfo);
}

static void *al5_dmabuf_kmap(struct dma_buf *dbuf, unsigned long page_num)
{
	struct codec_dma_buf_priv *dinfo = dbuf->priv;
	void *vaddr = dinfo->buffer->cpu_mem;

	return vaddr + page_num * PAGE_SIZE;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 18, 0)
static int codec_dmabuf_vmap(struct dma_buf *dbuf, struct iosys_map *map)
#elif LINUX_VERSION_CODE > KERNEL_VERSION(5, 10, 0)
static int codec_dmabuf_vmap(struct dma_buf *dbuf, struct dma_buf_map *map)
#else
static void *codec_dmabuf_vmap(struct dma_buf *dbuf)
#endif
{
	struct codec_dma_buf_priv *dinfo = dbuf->priv;
	void *vaddr = dinfo->buffer->cpu_mem;

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 10, 0)
	if (!vaddr)
		return -ENOMEM;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 18, 0)
	iosys_map_set_vaddr(map, vaddr);
#else
	dma_buf_map_set_vaddr(map, vaddr);
#endif

	return 0;
#else
	return vaddr;
#endif
}

static const struct dma_buf_ops codec_dma_buf_ops = {
	.attach		= codec_dmabuf_attach,
	.detach		= codec_dmabuf_detach,
	.map_dma_buf	= codec_dmabuf_map,
	.unmap_dma_buf	= codec_dmabuf_unmap,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
/* the map_atomic interface was removed after 4.19 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
	.map_atomic	= al5_dmabuf_kmap,
#endif
/* the map interface was removed in 5.8 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
	.map		= al5_dmabuf_kmap,
#endif
#else
	.kmap_atomic	= al5_dmabuf_kmap,
	.kmap		= al5_dmabuf_kmap,
#endif
	.vmap		= codec_dmabuf_vmap,
	.mmap		= codec_dmabuf_mmap,
	.release	= codec_dmabuf_release,
};


static void define_export_info(struct dma_buf_export_info *exp_info,
			       size_t size,
			       void *priv)
{
	exp_info->owner = THIS_MODULE;
	exp_info->exp_name = KBUILD_MODNAME;
	exp_info->ops = &codec_dma_buf_ops;
	exp_info->flags = O_RDWR;
	exp_info->resv = NULL;
	exp_info->size = size;
	exp_info->priv = priv;
}

static struct sg_table *codec_get_base_sgt(struct codec_dma_buf_priv *dinfo)
{
	int ret;
	struct sg_table *sgt;
	struct codec_dma_buf *buf = dinfo->buffer;
	struct device *dev = dinfo->dev;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return NULL;

	// We can do that only because we use the incoherent DMA API ?
	// See kernel-doc comment of `dma_get_sgtable()`
	ret = dma_get_sgtable(dev, sgt, buf->cpu_mem, buf->dma_handle,
			      buf->size);
	if (ret < 0) {
		kfree(sgt);
		return NULL;
	}

	return sgt;

}

struct dma_buf *codec_dmabuf_wrap(struct device *dev, size_t size,
								struct codec_dma_buf *buffer,
								struct codec_client *client)
{
	struct dma_buf *dma_buf;


	struct codec_dma_buf_priv *dinfo;

	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	dinfo = kzalloc(sizeof(*dinfo), GFP_KERNEL);
	if (!dinfo)
		return ERR_PTR(-ENOMEM);

	dinfo->dev = get_device(dev);
	dinfo->client = client;
	dinfo->buffer = buffer;
	dinfo->dma_dir = DMA_BIDIRECTIONAL;
	dinfo->sgt_base = codec_get_base_sgt(dinfo);


	define_export_info(&exp_info,
			   buffer->size,
			   (void *)dinfo);

	if (!dinfo->sgt_base)
		dinfo->sgt_base = codec_get_base_sgt(dinfo);

	if (WARN_ON(!dinfo->sgt_base))
		return NULL;


	dma_buf = dma_buf_export(&exp_info);
	if (IS_ERR(dma_buf)) {
		pr_err("couldn't export dma buf\n");
		return ERR_PTR(-EINVAL);
	}

	return dma_buf;
}
