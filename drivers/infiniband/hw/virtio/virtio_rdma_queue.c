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

static bool virtio_rdma_cq_notify_now(struct virtio_rdma_cq *cq, uint32_t flags)
{
	uint32_t cq_notify;

	if (!cq->ibcq.comp_handler)
		return false;

	/* Read application shared notification state */
	cq_notify = READ_ONCE(cq->notify_flags);

	if ((cq_notify & VIRTIO_RDMA_NOTIFY_NEXT_COMPLETION) ||
	    ((cq_notify & VIRTIO_RDMA_NOTIFY_SOLICITED) &&
	     (flags & IB_SEND_SOLICITED))) {
		/*
		 * CQ notification is one-shot: Since the
		 * current CQE causes user notification,
		 * the CQ gets dis-aremd and must be re-aremd
		 * by the user for a new notification.
		 */
		WRITE_ONCE(cq->notify_flags, VIRTIO_RDMA_NOTIFY_NOT);

		return true;
	}
	return false;
}

void virtio_rdma_cq_ack(struct virtqueue *vq)
{
	struct virtio_rdma_cq *vcq;
	struct virtio_rdma_dev *rdev = vq->vdev->priv;
	struct scatterlist sg;
	bool notify;
	unsigned long flags;
	unsigned tmp;

	spin_lock_irqsave(&rdev->cq_vqs[vq->index - 1].lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((vcq = virtqueue_get_buf(vq, &tmp))) {
			atomic_inc(&vcq->cqe_cnt);
			vcq->cqe_put++;

			notify = virtio_rdma_cq_notify_now(vcq, vcq->queue[vcq->cqe_put % vcq->num_cqe].wc_flags);

			sg_init_one(&sg, &vcq->queue[vcq->cqe_enqueue % vcq->num_cqe], sizeof(*vcq->queue));
			virtqueue_add_inbuf(vcq->vq->vq, &sg, 1, vcq, GFP_KERNEL);
			vcq->cqe_enqueue++;

			if (notify) {
				vcq->ibcq.comp_handler(&vcq->ibcq,
						vcq->ibcq.cq_context);
			}
		}

		if (unlikely(virtqueue_is_broken(vq)))
			break;
	} while(!virtqueue_enable_cb(vq));
	spin_unlock_irqrestore(&rdev->cq_vqs[vq->index - 1].lock, flags);
}

int virtio_rdma_rq_free_buf (struct virtio_rdma_qp *vqp , int num) {
	struct virtio_rdma_rq_data *data;
	unsigned len;

	do {
		while ((data = virtqueue_get_buf(vqp->rq->vq, &len)) == NULL &&
			!virtqueue_is_broken(vqp->rq->vq))
			cpu_relax();

		if (virtqueue_is_broken(vqp->rq->vq))
			return -EIO;

		kfree(data->sge_sg);
		kfree(data);
		num--;
	} while (num);

	return 0;
}

int virtio_rdma_sq_free_buf (struct virtio_rdma_qp *vqp , int num) {
	struct virtio_rdma_sq_data *data;
	unsigned len;

	do {
		while ((data = virtqueue_get_buf(vqp->sq->vq, &len)) == NULL &&
			!virtqueue_is_broken(vqp->sq->vq))
			cpu_relax();

		if (virtqueue_is_broken(vqp->rq->vq))
			return -EIO;

		kfree(data->sge_sg);
		kfree(data);
		num--;
	} while (num);
	return 0;
}
