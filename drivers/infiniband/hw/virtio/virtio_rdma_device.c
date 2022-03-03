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

#include <uapi/linux/virtio_net.h>

static void init_device_attr(struct virtio_rdma_dev *rdev)
{
	uint32_t atomic_cap;

	virtio_cread(rdev->vdev, struct virtio_net_config, phys_port_cnt, &rdev->ib_dev.phys_port_cnt);

	memset(&rdev->attr, 0, sizeof(rdev->attr));
	virtio_cread_le(rdev->vdev, struct virtio_net_config, sys_image_guid, (uint64_t*)&rdev->attr.sys_image_guid);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, vendor_id, &rdev->attr.vendor_id);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, vendor_part_id, &rdev->attr.vendor_part_id);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, hw_ver, &rdev->attr.hw_ver);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_mr_size, &rdev->attr.max_mr_size);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, page_size_cap, &rdev->attr.page_size_cap);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_qp, (uint32_t*)&rdev->attr.max_qp);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_qp_wr,(uint32_t*) &rdev->attr.max_qp_wr);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, device_cap_flags, &rdev->attr.device_cap_flags);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_send_sge, (uint32_t*)&rdev->attr.max_send_sge);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_recv_sge, (uint32_t*)&rdev->attr.max_recv_sge);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_sge_rd, (uint32_t*)&rdev->attr.max_sge_rd);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_cq, (uint32_t*)&rdev->attr.max_cq);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_cqe, (uint32_t*)&rdev->attr.max_cqe);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_mr, (uint32_t*)&rdev->attr.max_mr);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_pd, (uint32_t*)&rdev->attr.max_pd);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_qp_rd_atom, (uint32_t*)&rdev->attr.max_qp_rd_atom);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_res_rd_atom, (uint32_t*)&rdev->attr.max_res_rd_atom);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_qp_init_rd_atom, (uint32_t*)&rdev->attr.max_qp_init_rd_atom);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, atomic_cap, &atomic_cap);
	rdev->attr.atomic_cap = virtio_rdma_atomic_cap_to_ib(atomic_cap);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_mw, (uint32_t*)&rdev->attr.max_mw);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_mcast_grp, (uint32_t*)&rdev->attr.max_mcast_grp);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_mcast_qp_attach, (uint32_t*)&rdev->attr.max_mcast_qp_attach);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_total_mcast_qp_attach, (uint32_t*)&rdev->attr.max_total_mcast_qp_attach);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_ah, (uint32_t*)&rdev->attr.max_ah);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_fast_reg_page_list_len, &rdev->attr.max_fast_reg_page_list_len);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_pi_fast_reg_page_list_len, &rdev->attr.max_pi_fast_reg_page_list_len);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, max_pkeys, &rdev->attr.max_pkeys);
	virtio_cread_le(rdev->vdev, struct virtio_net_config, local_ca_ack_delay, &rdev->attr.local_ca_ack_delay);
}

int init_device(struct virtnet_adev* vadev, struct virtio_rdma_dev *dev)
{
	int rc = 0;
	uint32_t max_cq, max_srq, max_qp;

	init_device_attr(dev);
	max_cq = dev->attr.max_cq;
	max_qp = dev->attr.max_qp;
	max_srq = dev->attr.max_srq;
	pr_info("Init vq: cq %u qp %u srq %u", max_cq, max_qp, max_srq);

	dev->ctrl_vq = vadev->ctrl_vq;

	dev->cq_vqs = vadev->cq_vqs;
	dev->cqs = kcalloc(max_cq, sizeof(*dev->cqs), GFP_KERNEL);

	dev->qp_vqs = vadev->qp_vqs;
	dev->qps = kcalloc(max_qp, sizeof(*dev->qps), GFP_KERNEL);

	pr_info("VIRTIO-RDMA INIT qp_vqs %d\n", dev->qp_vqs[max_qp * 2 - 1].vq->index);

	mutex_init(&dev->port_mutex);
	dev->ib_active = true;

	return rc;
}

void fini_device(struct virtio_rdma_dev *dev)
{
	dev->vdev->config->reset(dev->vdev);
	dev->vdev->config->del_vqs(dev->vdev);
}
