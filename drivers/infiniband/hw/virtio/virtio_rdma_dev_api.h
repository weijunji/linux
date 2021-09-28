/*
 * Virtio RDMA device: Virtio communication message
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
#ifndef __VIRTIO_RDMA_DEV_API__
#define __VIRTIO_RDMA_DEV_API__

#include <linux/kernel.h>
#include <linux/types.h>
#include <rdma/ib_verbs.h>

#include <uapi/rdma/virtio_rdma_abi.h>

struct virtio_rdma_config {
    __le32         phys_port_cnt;

    __le64         sys_image_guid;
    __le32         vendor_id;
    __le32         vendor_part_id;
    __le32         hw_ver;
    __le64         max_mr_size;
    __le64         page_size_cap;
    __le32         max_qp;
    __le32         max_qp_wr;
    __le64         device_cap_flags;
    __le32         max_send_sge;
    __le32         max_recv_sge;
    __le32         max_sge_rd;
    __le32         max_cq;
    __le32         max_cqe;
    __le32         max_mr;
    __le32         max_pd;
    __le32         max_qp_rd_atom;
    __le32         max_ee_rd_atom;
    __le32         max_res_rd_atom;
    __le32         max_qp_init_rd_atom;
    __le32         max_ee_init_rd_atom;
    __le32         atomic_cap;
    __le32         max_ee;
    __le32         max_rdd;
    __le32         max_mw;
    __le32         max_mcast_grp;
    __le32         max_mcast_qp_attach;
    __le32         max_total_mcast_qp_attach;
    __le32         max_ah;
    __le32         max_srq;
    __le32         max_srq_wr;
    __le32         max_srq_sge;
    __le32         max_fast_reg_page_list_len;
    __le32         max_pi_fast_reg_page_list_len;
    __le16         max_pkeys;
	__u8           local_ca_ack_delay;

    __u8           reserved[128];
} __attribute__((packed));

#define VIRTIO_RDMA_CTRL_OK	0
#define VIRTIO_RDMA_CTRL_ERR	1

struct control_buf {
	__u8 cmd;
	__u8 status;
};

enum {
	VIRTIO_CMD_ILLEGAL,
	VIRTIO_CMD_QUERY_PORT,
	VIRTIO_CMD_CREATE_CQ,
	VIRTIO_CMD_DESTROY_CQ,
	VIRTIO_CMD_CREATE_PD,
	VIRTIO_CMD_DESTROY_PD,
	VIRTIO_CMD_GET_DMA_MR,
	VIRTIO_CMD_CREATE_MR,
	VIRTIO_CMD_MAP_MR_SG,
	VIRTIO_CMD_REG_USER_MR,
	VIRTIO_CMD_DEREG_MR,
	VIRTIO_CMD_CREATE_QP,
    VIRTIO_CMD_MODIFY_QP,
	VIRTIO_CMD_QUERY_QP,
    VIRTIO_CMD_DESTROY_QP,
	VIRTIO_CMD_QUERY_GID,
	VIRTIO_CMD_CREATE_UC,
	VIRTIO_CMD_DEALLOC_UC,
	VIRTIO_CMD_QUERY_PKEY,
	VIRTIO_CMD_ADD_GID,
    VIRTIO_CMD_DEL_GID,
    VIRTIO_CMD_REQ_NOTIFY_CQ,
};

struct cmd_query_port {
	__u32 port;
};

struct cmd_create_cq {
	__u32 cqe;
};

struct rsp_create_cq {
	__u32 cqn;
};

struct cmd_destroy_cq {
	__u32 cqn;
};

struct cmd_create_pd {
	__u32 ctx_handle;
};

struct rsp_create_pd {
	__u32 pdn;
};

struct cmd_destroy_pd {
	__u32 pdn;
};

struct cmd_create_mr {
	__u32 pdn;
	__u32 access_flags;

	__u32 max_num_sg;
};

struct rsp_create_mr {
	__u32 mrn;
	__u32 lkey;
	__u32 rkey;
};

struct cmd_map_mr_sg {
	__u32 mrn;
	__u64 start;
	__u32 npages;

	__u64 pages;
};

struct rsp_map_mr_sg {
	__u32 npages;
};

struct cmd_reg_user_mr {
	__u32 pdn;
	__u32 access_flags;
	__u64 start;
	__u64 length;
	__u64 virt_addr;

	__u64 pages;
	__u32 npages;
};

struct rsp_reg_user_mr {
	__u32 mrn;
	__u32 lkey;
	__u32 rkey;
};

struct cmd_dereg_mr {
    __u32 mrn;

	__u8 is_user_mr;
};

struct cmd_create_qp {
    __u32 pdn;
    __u8 qp_type;
    __u32 max_send_wr;
    __u32 max_send_sge;
    __u32 send_cqn;
    __u32 max_recv_wr;
    __u32 max_recv_sge;
    __u32 recv_cqn;
    __u8 is_srq;
    __u32 srq_handle;
};

struct rsp_create_qp {
	__u32 qpn;
};

struct cmd_modify_qp {
    __u32 qpn;
    __u32 attr_mask;
    struct virtio_rdma_qp_attr attrs;
};

struct rsp_modify_qp {
    __u32 qpn;
};

struct cmd_destroy_qp {
    __u32 qpn;
};

struct cmd_query_qp {
	__u32 qpn;
	__u32 attr_mask;
};

struct rsp_query_qp {
	struct virtio_rdma_qp_attr attr;
};

struct cmd_query_gid {
    __u32 port;
	__u32 index;
};

struct cmd_create_uc {
	__u64 pfn;
};

struct rsp_create_uc {
	__u32 ctx_handle;
};

struct cmd_dealloc_uc {
	__u32 ctx_handle;
};

struct cmd_query_pkey {
	__u32 port;
	__u16 index;
};

struct rsp_query_pkey {
	__u16 pkey;
};

struct cmd_req_notify {
	__u32 cqn;
	__u32 flags;
};

struct rsp_req_notify {
	__u32 status;
};

#endif
