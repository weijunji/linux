/*
 * Virtio RDMA device: Driver main data types
 *
 * Copyright (C) 2019 Yuval Shaia Oracle Corporation
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

#ifndef __VIRTIO_RDMA__
#define __VIRTIO_RDMA__

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <rdma/ib_verbs.h>

#include "virtio_rdma_ib.h"

struct virtio_rdma_dev {
	struct ib_device ib_dev;
	struct ib_device_attr	attr;

	struct virtio_device *vdev;
	struct virtqueue *ctrl_vq;

	/* To protect the vq operations for the controlq */
	spinlock_t ctrl_lock;

	// wait_queue_head_t acked; /* arm on send to host, release on recv */
	struct net_device *netdev;

	struct virtio_rdma_vq* cq_vqs;
	struct virtio_rdma_cq** cqs;

	struct virtio_rdma_vq* qp_vqs;

	atomic_t num_qp;
	atomic_t num_cq;
	atomic_t num_ah;

	struct list_head pending_mmaps;
	spinlock_t pending_mmaps_lock;

	// only for modify_port ?
	struct mutex port_mutex;
	u32 port_cap_mask;
	// TODO: check ib_active before operations
	bool ib_active;

	bool fast_doorbell;
};

static inline struct virtio_rdma_dev *to_vdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct virtio_rdma_dev, ib_dev);
}

#define virtio_rdma_dbg(ibdev, fmt, ...)                                               \
	ibdev_dbg(ibdev, "%s: " fmt, __func__, ##__VA_ARGS__)

#endif
