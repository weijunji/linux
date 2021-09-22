/*
 * Virtio RDMA mmap: mmap virtqueue to userspace
 *
 * Copyright (C) 2021 Junji Wei Bytedance Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/virtio_ring.h>
#include <rdma/uverbs_ioctl.h>

#include "virtio_rdma.h"
#include "virtio_rdma_loc.h"

void virtio_rdma_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	struct virtio_rdma_user_mmap_entry *entry = to_ventry(rdma_entry);

	kfree(entry);
}

int virtio_rdma_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma)
{
	struct virtio_rdma_ucontext *uctx = to_vucontext(ctx);
	size_t size = vma->vm_end - vma->vm_start;
	struct rdma_user_mmap_entry *rdma_entry;
	struct virtio_rdma_user_mmap_entry *entry;
	int rc = -EINVAL;

	if (vma->vm_start & (PAGE_SIZE - 1)) {
		pr_warn("mmap not page aligned\n");
		return -EINVAL;
	}

	rdma_entry = rdma_user_mmap_entry_get(&uctx->ibucontext, vma);
	if (!rdma_entry) {
		pr_err("mmap lookup failed: %lu, %#zx\n", vma->vm_pgoff, size);
		return -EINVAL;
	}
	entry = to_ventry(rdma_entry);

	if (entry->type == VIRTIO_RDMA_MMAP_CQ) {
		// TODO: remove me, only for debug
		((char*)entry->cq_buf)[0] = 'W';
		// FIXME: buf is not align to page?
		rc = remap_pfn_range(vma, vma->vm_start,
			       page_to_pfn(virt_to_page(entry->cq_buf)),
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);
		if (rc) {
			pr_warn("remap_pfn_range failed: %lu, %zu\n", vma->vm_pgoff,
				size);
			goto out;
		}
	} else if (entry->type == VIRTIO_RDMA_MMAP_QP) {
		uint64_t vq_size = PAGE_ALIGN(vring_size(virtqueue_get_vring_size(entry->queue), SMP_CACHE_BYTES));
		WARN_ON(vq_size + entry->ubuf_size + PAGE_SIZE != vma->vm_end - vma->vm_start);

		// doorbell
		rc = io_remap_pfn_range(vma, vma->vm_start,
			       vmalloc_to_pfn(entry->queue->priv),
			       PAGE_SIZE, vma->vm_page_prot);

		// vring
		rc = remap_pfn_range(vma, vma->vm_start + PAGE_SIZE,
			       page_to_pfn(virt_to_page((virtqueue_get_vring(entry->queue)->desc))),
			       vq_size, vma->vm_page_prot);

		// user buffer
		rc = remap_pfn_range(vma, vma->vm_start + PAGE_SIZE + vq_size,
			       page_to_pfn(virt_to_page(entry->ubuf)), entry->ubuf_size,
				   vma->vm_page_prot);

		if (rc) {
			pr_warn("remap_pfn_range failed: %lu, %zu\n", vma->vm_pgoff,
				size);
			goto out;
		}
	} else {
		pr_err("Invalid type");
	}

out:
	rdma_user_mmap_entry_put(rdma_entry);

	return rc;
}
