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

#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <uapi/linux/virtio_ids.h>

#include "virtio_rdma.h"
#include "virtio_rdma_device.h"
#include "virtio_rdma_ib.h"
#include "virtio_rdma_netdev.h"

#include "../../../virtio/virtio_pci_common.h"

static int virtio_rdma_probe(struct auxiliary_device *adev,
							const struct auxiliary_device_id *id)
{
	struct virtio_rdma_dev *ri;
	struct virtnet_adev* vadev;
	int rc = -EIO;

	vadev = to_vnet_adev(adev);

	ri = ib_alloc_device(virtio_rdma_dev, ib_dev);
	if (!ri) {
		pr_err("Fail to allocate IB device\n");
		rc = -ENOMEM;
		goto out;
	}
	dev_set_drvdata(&adev->dev, ri);
	virtnet_set_roce_priv(vadev->vdev->priv, ri);

	// FIXME: check if is virtio-pci device
	if (to_vp_device(vadev->vdev)->mdev.notify_offset_multiplier != PAGE_SIZE) {
		pr_warn("notify_offset_multiplier is NOT equal to PAGE_SIZE");
		ri->fast_doorbell = false;
	} else {
		ri->fast_doorbell = true;
	}

	ri->vdev = vadev->vdev;

	spin_lock_init(&ri->ctrl_lock);

	rc = init_device(vadev, ri);
	if (rc) {
		pr_err("Fail to connect to device\n");
		goto out_dealloc_ib_device;
	}

	rc = init_netdev(vadev, ri);
	if (rc) {
		pr_err("Fail to connect to NetDev layer\n");
		goto out_fini_device;
	}

	rc = virtio_rdma_register_ib_device(ri);
	if (rc) {
		pr_err("Fail to connect to IB layer\n");
		goto out_fini_netdev;
	}

	pr_info("VirtIO RDMA device %d probed %s\n", ri->vdev->index, id->name);

	goto out;

out_fini_netdev:
	fini_netdev(ri);

out_fini_device:
	fini_device(ri);

out_dealloc_ib_device:
	ib_dealloc_device(&ri->ib_dev);

	virtnet_set_roce_priv(vadev->vdev->priv, NULL);
	dev_set_drvdata(&adev->dev, NULL);

out:
	return rc;
}

static void virtio_rdma_remove(struct auxiliary_device *adev)
{
	struct virtio_rdma_dev *ri = dev_get_drvdata(&adev->dev);
	struct virtnet_adev* vadev = to_vnet_adev(adev);

	if (!ri)
		return;

	dev_set_drvdata(&adev->dev, NULL);
	virtnet_set_roce_priv(vadev->vdev->priv, NULL);

	virtio_rdma_unregister_ib_device(ri);

	fini_netdev(ri);

	fini_device(ri);

	ib_dealloc_device(&ri->ib_dev);

	pr_info("VirtIO RDMA device %d removed\n", ri->vdev->index);
}

static const struct auxiliary_device_id vnetr_id_table[] = {
	{ .name = VNET_ADEV_NAME ".roce", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, vnetr_id_table);

static struct auxiliary_driver vnetr_driver = {
	.driver.name	= KBUILD_MODNAME,
	.driver.owner	= THIS_MODULE,
	.name = "roce",
	.id_table = vnetr_id_table,
	.probe = virtio_rdma_probe,
	.remove = virtio_rdma_remove,
};

static int __init virtio_rdma_init(void)
{
	int rc;

	rc = auxiliary_driver_register(&vnetr_driver);
	if (rc) {
		pr_err("%s: Fail to register vnet.roce driver (%d)\n", __func__,
		       rc);
		return rc;
	}

	return 0;
}

static void __exit virtio_rdma_fini(void)
{
	auxiliary_driver_unregister(&vnetr_driver);
}

module_init(virtio_rdma_init);
module_exit(virtio_rdma_fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_AUTHOR("Yuval Shaia, Junji Wei");
MODULE_DESCRIPTION("Virtio Net RoCE driver");
MODULE_LICENSE("Dual BSD/GPL");
