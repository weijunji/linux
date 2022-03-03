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

	rdev = virtnet_get_roce_priv(vq->vdev->priv);
	// vcq->vq's index is start from 1, 0 is ctrl vq
	vcq = rdev->cqs[vq->index - 1];

	if (vcq && vcq->ibcq.comp_handler)
		vcq->ibcq.comp_handler(&vcq->ibcq, vcq->ibcq.cq_context);
}

static int virtio_rdma_qp_chk_cap(struct virtio_rdma_dev *dev,
								struct ib_qp_cap *cap, int has_srq)
{
	if (cap->max_send_wr > dev->attr.max_qp_wr) {
		pr_warn("invalid send wr = %d > %d\n",
			cap->max_send_wr, dev->attr.max_qp_wr);
		goto err1;
	}

	if (cap->max_send_sge > dev->attr.max_send_sge) {
		pr_warn("invalid send sge = %d > %d\n",
			cap->max_send_sge, dev->attr.max_send_sge);
		goto err1;
	}

	if (!has_srq) {
		if (cap->max_recv_wr > dev->attr.max_qp_wr) {
			pr_warn("invalid recv wr = %d > %d\n",
				cap->max_recv_wr, dev->attr.max_qp_wr);
			goto err1;
		}

		if (cap->max_recv_sge > dev->attr.max_recv_sge) {
			pr_warn("invalid recv sge = %d > %d\n",
				cap->max_recv_sge, dev->attr.max_recv_sge);
			goto err1;
		}
	}

	// TODO: check max_inline_data

	return 0;

err1:
	return -EINVAL;
}

int virtio_rdma_qp_chk_init(struct virtio_rdma_dev *dev,
							struct ib_qp_init_attr *init)
{
	struct ib_qp_cap *cap = &init->cap;
	int port_num = init->port_num;

	// TODO: check qp type
	switch (init->qp_type) {
	case IB_QPT_SMI:
	case IB_QPT_GSI:
	case IB_QPT_RC:
	case IB_QPT_UC:
	case IB_QPT_UD:
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!init->recv_cq || !init->send_cq) {
		pr_warn("missing cq\n");
		goto err1;
	}

	if (virtio_rdma_qp_chk_cap(dev, cap, !!init->srq))
		goto err1;

	if (init->qp_type == IB_QPT_SMI || init->qp_type == IB_QPT_GSI) {
		if (!rdma_is_port_valid(&dev->ib_dev, port_num)) {
			pr_warn("invalid port = %d\n", port_num);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}
