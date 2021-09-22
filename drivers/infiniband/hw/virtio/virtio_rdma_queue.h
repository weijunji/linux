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
#ifndef __VIRTIO_RDMA_QUEUE_H__
#define __VIRTIO_RDMA_QUEUE_H__

#include "virtio_rdma_ib.h"
#include "virtio_rdma_dev_api.h"

struct scatterlist;

struct virtio_rdma_sq_data {
    struct virtio_rdma_qp *qp;
    struct virtio_rdma_cmd_post_send cmd;
    struct scatterlist *sge_sg;
    int status;
};

struct virtio_rdma_rq_data {
    struct virtio_rdma_qp *qp;
    struct virtio_rdma_cmd_post_recv cmd;
    struct scatterlist *sge_sg;
    int status;
};

void virtio_rdma_cq_ack(struct virtqueue *vq);

#endif
