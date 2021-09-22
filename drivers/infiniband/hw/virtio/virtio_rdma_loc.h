/*
 * Virtio RDMA loc: local header file
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

#ifndef __VIRTIO_RDMA_LOC_H__
#define __VIRTIO_RDMA_LOC_H__

#include <linux/types.h>
#include <linux/kref.h>

/* virtio_rdma_mmap.c */
struct virtio_rdma_user_mmap_entry {
    struct rdma_user_mmap_entry rdma_entry;

	#define VIRTIO_RDMA_MMAP_CQ 1
	#define VIRTIO_RDMA_MMAP_QP 2
	uint8_t type;

	union {
		struct {
			struct virtqueue *queue;
			void* ubuf;
			uint64_t ubuf_size;
		};
		void* cq_buf;
	};
};

static inline struct virtio_rdma_user_mmap_entry* to_ventry
(struct rdma_user_mmap_entry *rdma_entry) {
	return container_of(rdma_entry, struct virtio_rdma_user_mmap_entry,
	                    rdma_entry);
}

int virtio_rdma_mmap(struct ib_ucontext *context, struct vm_area_struct *vma);
void virtio_rdma_mmap_free(struct rdma_user_mmap_entry *rdma_entry);

#endif
