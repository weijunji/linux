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

#include "virtio_rdma_netdev.h"

struct virtio_rdma_netdev {
	struct virtio_rdma_dev *ri;
};

netdev_tx_t dummy_xmit(struct sk_buff *skb, struct net_device *dev) {
	return NETDEV_TX_OK;
}

static const struct net_device_ops dummy_netdev_ops = {
	.ndo_start_xmit = dummy_xmit,
};

int init_netdev(struct virtio_rdma_dev *ri)
{
	struct virtio_rdma_netdev *vrndi;
	struct net_device *dev;

	dev = alloc_netdev(sizeof(struct virtio_rdma_netdev), "virtio_rdma%d", NET_NAME_UNKNOWN, ether_setup);
	if (!dev) {
		return -ENOMEM;
	}
	dev->netdev_ops = &dummy_netdev_ops;
	eth_hw_addr_random(dev);

	SET_NETDEV_DEV(dev, &ri->vdev->dev);
	vrndi = netdev_priv(dev);
	vrndi->ri = ri;
	ri->netdev = dev;

	if (!ri->netdev) {
		pr_err("failed to get backend net device\n");
		return -ENODEV;
	}
	dev_hold(ri->netdev);

	if (register_netdev(dev) < 0)
		return -EIO;

	return 0;
}

void fini_netdev(struct virtio_rdma_dev *ri)
{
	if (ri->netdev) {
		unregister_netdev(ri->netdev);
		dev_put(ri->netdev);
		free_netdev(ri->netdev);
		ri->netdev = NULL;
	}
}
