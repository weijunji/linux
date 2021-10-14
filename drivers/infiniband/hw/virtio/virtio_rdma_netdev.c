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

int init_netdev(struct virtio_rdma_dev *ri)
{
	struct pci_dev* pdev_net;
	struct virtio_pci_device *vp_dev = to_vp_device(ri->vdev);
	struct virtio_pci_device *vnet_pdev;
	void* priv;

	pdev_net = pci_get_slot(vp_dev->pci_dev->bus, PCI_DEVFN(PCI_SLOT(vp_dev->pci_dev->devfn), 0));
	if (!pdev_net) {
		pr_err("failed to find paired net device\n");
		return -ENODEV;
	}

	if (pdev_net->vendor != PCI_VENDOR_ID_REDHAT_QUMRANET ||
	    pdev_net->subsystem_device != VIRTIO_ID_NET) {
		pr_err("failed to find paired virtio-net device\n");
		pci_dev_put(pdev_net);
		return -ENODEV;
	}

	vnet_pdev = pci_get_drvdata(pdev_net);
	pci_dev_put(pdev_net);

	priv = vnet_pdev->vdev.priv;
	/* get netdev from virtnet_info, which is netdev->priv */
	ri->netdev = priv - ALIGN(sizeof(struct net_device), NETDEV_ALIGN);

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
