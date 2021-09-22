/*
 * Virtio RDMA queue pair operation
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

#include <linux/virtio.h>

#include "virtio_rdma.h"
#include "virtio_rdma_queue.h"

void virtio_rdma_cq_ack(struct virtqueue *vq)
{
	struct virtio_rdma_dev *rdev;
	struct virtio_rdma_cq *vcq;

	rdev = vq->vdev->priv;
	// vcq->vq's index is start from 1, 0 is ctrl vq
	vcq = rdev->cqs[vq->index - 1];

	if (vcq && vcq->ibcq.comp_handler)
		vcq->ibcq.comp_handler(&vcq->ibcq, vcq->ibcq.cq_context);
}
