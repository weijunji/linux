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
#include <rdma/uverbs_ioctl.h>

#include "virtio_rdma.h"
#include "virtio_rdma_loc.h"

void virtio_rdma_mmap_release(struct kref *ref)
{
	struct virtio_rdma_mminfo *ip = container_of(ref,
					struct virtio_rdma_mminfo, ref);
	struct virtio_rdma_dev *rxe = to_vdev(ip->context->device);

	spin_lock_bh(&rxe->pending_mmaps_lock);

	if (!list_empty(&ip->pending_mmaps))
		list_del(&ip->pending_mmaps);

	spin_unlock_bh(&rxe->pending_mmaps_lock);

	kfree(ip);
}

static void virtio_rdma_vma_open(struct vm_area_struct *vma)
{
	struct virtio_rdma_mminfo *ip = vma->vm_private_data;

	kref_get(&ip->ref);
}

static void virtio_rdma_vma_close(struct vm_area_struct *vma)
{
	struct virtio_rdma_mminfo *ip = vma->vm_private_data;

	kref_put(&ip->ref, virtio_rdma_mmap_release);
}

static const struct vm_operations_struct virtio_rdma_vm_ops = {
	.open = virtio_rdma_vma_open,
	.close = virtio_rdma_vma_close,
};

int virtio_rdma_mmap(struct ib_ucontext *context, struct vm_area_struct *vma)
{
    return 0;
}
