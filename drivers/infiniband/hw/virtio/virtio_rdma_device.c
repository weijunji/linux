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
#include "virtio_rdma_dev_api.h"
#include "virtio_rdma_queue.h"

static void init_device_attr (struct virtio_rdma_dev *rdev)
{
	uint32_t atomic_cap;

	virtio_cread(rdev->vdev, struct virtio_rdma_config, phys_port_cnt, &rdev->ib_dev.phys_port_cnt);

	memset(&rdev->attr, 0, sizeof(rdev->attr));
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, sys_image_guid, (uint64_t*)&rdev->attr.sys_image_guid);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, vendor_id, &rdev->attr.vendor_id);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, vendor_part_id, &rdev->attr.vendor_part_id);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, hw_ver, &rdev->attr.hw_ver);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_mr_size, &rdev->attr.max_mr_size);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, page_size_cap, &rdev->attr.page_size_cap);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_qp, (uint32_t*)&rdev->attr.max_qp);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_qp_wr,(uint32_t*) &rdev->attr.max_qp_wr);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, device_cap_flags, &rdev->attr.device_cap_flags);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_send_sge, (uint32_t*)&rdev->attr.max_send_sge);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_recv_sge, (uint32_t*)&rdev->attr.max_recv_sge);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_sge_rd, (uint32_t*)&rdev->attr.max_sge_rd);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_cq, (uint32_t*)&rdev->attr.max_cq);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_cqe, (uint32_t*)&rdev->attr.max_cqe);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_mr, (uint32_t*)&rdev->attr.max_mr);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_pd, (uint32_t*)&rdev->attr.max_pd);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_qp_rd_atom, (uint32_t*)&rdev->attr.max_qp_rd_atom);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_res_rd_atom, (uint32_t*)&rdev->attr.max_res_rd_atom);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_qp_init_rd_atom, (uint32_t*)&rdev->attr.max_qp_init_rd_atom);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, atomic_cap, &atomic_cap);
	rdev->attr.atomic_cap = virtio_rdma_atomic_cap_to_ib(atomic_cap);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_mw, (uint32_t*)&rdev->attr.max_mw);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_mcast_grp, (uint32_t*)&rdev->attr.max_mcast_grp);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_mcast_qp_attach, (uint32_t*)&rdev->attr.max_mcast_qp_attach);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_total_mcast_qp_attach, (uint32_t*)&rdev->attr.max_total_mcast_qp_attach);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_ah, (uint32_t*)&rdev->attr.max_ah);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_fast_reg_page_list_len, &rdev->attr.max_fast_reg_page_list_len);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_pi_fast_reg_page_list_len, &rdev->attr.max_pi_fast_reg_page_list_len);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, max_pkeys, &rdev->attr.max_pkeys);
	virtio_cread_le(rdev->vdev, struct virtio_rdma_config, local_ca_ack_delay, &rdev->attr.local_ca_ack_delay);
}

int init_device(struct virtio_rdma_dev *dev)
{
	int rc = -ENOMEM;
	int64_t i, cur_vq = 1, total_vqs = 1; // first for ctrl_vq
	struct virtqueue **vqs;
	vq_callback_t **cbs;
	const char **names;
	uint32_t max_cq, max_srq, max_qp;

	init_device_attr(dev);
	max_cq = dev->attr.max_cq;
	max_qp = dev->attr.max_qp;
	max_srq = dev->attr.max_srq;
	pr_info("Init vq: cq %u qp %u srq %u", max_cq, max_qp, max_srq);

	total_vqs += max_cq;
	total_vqs += max_qp * 2;

	dev->cq_vqs = kcalloc(max_cq, sizeof(*dev->cq_vqs), GFP_ATOMIC);
	dev->cqs = kcalloc(max_cq, sizeof(*dev->cqs), GFP_ATOMIC);

	dev->qp_vqs = kcalloc(max_qp * 2, sizeof(*dev->qp_vqs), GFP_ATOMIC);

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
