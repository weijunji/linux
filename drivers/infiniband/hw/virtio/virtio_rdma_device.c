/*
 * Virtio RDMA device: Device related functions and data
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

#include <linux/virtio_config.h>

#include "virtio_rdma.h"
/*
static void rdma_ctrl_ack(struct virtqueue *vq)
{
	struct virtio_rdma_dev *dev = vq->vdev->priv;

	wake_up(&dev->acked);

	printk("%s\n", __func__);
}
*/

int init_device(struct virtio_rdma_dev *dev)
{
	int rc = -ENOMEM;
	int64_t i, cur_vq = 1, total_vqs = 1; // first for ctrl_vq
	struct virtqueue **vqs;
	vq_callback_t **cbs;
	const char **names;
	uint32_t max_cq;
	uint32_t max_qp;

	// init cq virtqueue
	virtio_cread(dev->vdev, struct virtio_rdma_config, max_cq, &max_cq);
	virtio_cread(dev->vdev, struct virtio_rdma_config, max_qp, &max_qp);
	dev->ib_dev.attrs.max_cq = max_cq;
	dev->ib_dev.attrs.max_qp = max_qp;
	dev->ib_dev.attrs.max_ah = 64; // TODO: read from host
	dev->ib_dev.attrs.max_cqe = 64; // TODO: read from host, size of virtqueue
	pr_info("Device max cq %d\n", dev->ib_dev.attrs.max_cq);

	total_vqs += max_cq;
	total_vqs += max_qp * 2;

	dev->cq_vqs = kcalloc(max_cq, sizeof(*dev->cq_vqs), GFP_ATOMIC);
	dev->cqs = kcalloc(max_cq, sizeof(*dev->cqs), GFP_ATOMIC);

	dev->qp_vqs = kcalloc(max_qp * 2, sizeof(*dev->qp_vqs), GFP_ATOMIC);
	dev->qp_vq_using = kzalloc(max_qp * sizeof(*dev->qp_vq_using), GFP_ATOMIC);
	for (i = 0; i < max_qp; i++) {
		dev->qp_vq_using[i] = -1;
	}
	spin_lock_init(&dev->qp_using_lock);

	vqs = kmalloc_array(total_vqs, sizeof(*vqs), GFP_ATOMIC);
	if (!vqs)
		goto err_vq;
		
	cbs = kmalloc_array(total_vqs, sizeof(*cbs), GFP_ATOMIC);
	if (!cbs)
		goto err_callback;

	names = kmalloc_array(total_vqs, sizeof(*names), GFP_ATOMIC);
	if (!names)
		goto err_names;

	names[0] = "ctrl";
	// cbs[0] = rdma_ctrl_ack;
	cbs[0] = NULL;

	for (i = 0; i < max_cq; i++, cur_vq++) {
		sprintf(dev->cq_vqs[i].name, "cq.%lld", i);
		names[cur_vq] = dev->cq_vqs[i].name;
		cbs[cur_vq] = virtio_rdma_cq_ack;
	}

	for (i = 0; i < max_qp * 2; i += 2, cur_vq += 2) {
		sprintf(dev->qp_vqs[i].name, "sqp.%lld", i);
		sprintf(dev->qp_vqs[i+1].name, "rqp.%lld", i);
		names[cur_vq] = dev->qp_vqs[i].name;
		names[cur_vq+1] = dev->qp_vqs[i+1].name;
		cbs[cur_vq] = NULL;
		cbs[cur_vq+1] = NULL;
	}

	rc = virtio_find_vqs(dev->vdev, total_vqs, vqs, cbs, names, NULL);
	if (rc) {
		pr_info("error: %d\n", rc);
		goto err;
	}

	dev->ctrl_vq = vqs[0];
	cur_vq = 1;
	for (i = 0; i < max_cq; i++, cur_vq++) {
		dev->cq_vqs[i].vq = vqs[cur_vq];
		dev->cq_vqs[i].idx = i;
		spin_lock_init(&dev->cq_vqs[i].lock);
	}

	for (i = 0; i < max_qp * 2; i += 2, cur_vq += 2) {
		dev->qp_vqs[i].vq = vqs[cur_vq];
		dev->qp_vqs[i+1].vq = vqs[cur_vq+1];
		dev->qp_vqs[i].idx = i / 2;
		dev->qp_vqs[i+1].idx = i / 2;
		spin_lock_init(&dev->qp_vqs[i].lock);
		spin_lock_init(&dev->qp_vqs[i+1].lock);
	}
	pr_info("VIRTIO-RDMA INIT qp_vqs %d\n", dev->qp_vqs[max_qp * 2 - 1].vq->index);

	mutex_init(&dev->port_mutex);
	dev->ib_active = true;

err:
	kfree(names);
err_names:
	kfree(cbs);
err_callback:
	kfree(vqs);
err_vq:
	return rc;
}

void fini_device(struct virtio_rdma_dev *dev)
{
	dev->vdev->config->reset(dev->vdev);
	dev->vdev->config->del_vqs(dev->vdev);
}
