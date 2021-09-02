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

#ifndef __VIRTIO_RDMA_DEVICE__
#define __VIRTIO_RDMA_DEVICE__

#define VIRTIO_RDMA_BOARD_ID	1
#define VIRTIO_RDMA_HW_NAME	"virtio-rdma"
#define VIRTIO_RDMA_HW_REV	1
#define VIRTIO_RDMA_DRIVER_VER	"1.0"

int init_device(struct virtio_rdma_dev *dev);
void fini_device(struct virtio_rdma_dev *dev);

#endif
