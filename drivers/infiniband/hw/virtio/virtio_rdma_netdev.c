/*
 * Virtio RDMA device
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

#include <linux/netdevice.h>
#include <linux/pci_ids.h>
#include <linux/virtio_ids.h>

#include "../../../virtio/virtio_pci_common.h"
#include "virtio_rdma_netdev.h"

int init_netdev(struct virtnet_adev* vadev, struct virtio_rdma_dev *ri)
{
	ri->netdev = vadev->ndev;

	if (!ri->netdev) {
		pr_err("failed to get backend net device\n");
		return -ENODEV;
	}
	dev_hold(ri->netdev);
	return 0;
}

void fini_netdev(struct virtio_rdma_dev *ri)
{
	if (ri->netdev) {
		dev_put(ri->netdev);
		ri->netdev = NULL;
	}
}
