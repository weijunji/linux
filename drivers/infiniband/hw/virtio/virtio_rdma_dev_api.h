/*
 * Virtio RDMA device: Virtio communication message
 *
 * Copyright (C) 2019 Junji Wei Bytedance Inc.
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

#define VIRTIO_RDMA_CTRL_OK	0
#define VIRTIO_RDMA_CTRL_ERR	1

struct control_buf {
	__u8 cmd;
	__u8 status;
};

enum {
	VIRTIO_CMD_QUERY_DEVICE = 10,
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
};

const char* cmd_name[] = {
	[VIRTIO_CMD_QUERY_DEVICE] = "VIRTIO_CMD_QUERY_DEVICE",
	[VIRTIO_CMD_QUERY_PORT] = "VIRTIO_CMD_QUERY_PORT",
	[VIRTIO_CMD_CREATE_CQ] = "VIRTIO_CMD_CREATE_CQ",
	[VIRTIO_CMD_DESTROY_CQ] = "VIRTIO_CMD_DESTROY_CQ",
	[VIRTIO_CMD_CREATE_PD] = "VIRTIO_CMD_CREATE_PD",
	[VIRTIO_CMD_DESTROY_PD] = "VIRTIO_CMD_DESTROY_PD",
	[VIRTIO_CMD_GET_DMA_MR] = "VIRTIO_CMD_GET_DMA_MR",
	[VIRTIO_CMD_CREATE_MR] = "VIRTIO_CMD_CREATE_MR",
	[VIRTIO_CMD_MAP_MR_SG] = "VIRTIO_CMD_MAP_MR_SG",
	[VIRTIO_CMD_REG_USER_MR] = "VIRTIO_CMD_REG_USER_MR",
	[VIRTIO_CMD_DEREG_MR] = "VIRTIO_CMD_DEREG_MR",
	[VIRTIO_CMD_CREATE_QP] = "VIRTIO_CMD_CREATE_QP",
    [VIRTIO_CMD_MODIFY_QP] = "VIRTIO_CMD_MODIFY_QP",
    [VIRTIO_CMD_DESTROY_QP] = "VIRTIO_CMD_DESTROY_QP",
	[VIRTIO_CMD_QUERY_GID] = "VIRTIO_CMD_QUERY_GID",
	[VIRTIO_CMD_CREATE_UC] = "VIRTIO_CMD_CREATE_UC",
	[VIRTIO_CMD_DEALLOC_UC] = "VIRTIO_CMD_DEALLOC_UC",
	[VIRTIO_CMD_QUERY_PKEY] = "VIRTIO_CMD_QUERY_PKEY",
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

struct rsp_destroy_cq {
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

struct rsp_destroy_pd {
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

struct rsp_dereg_mr {
    __u32 mrn;
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

struct rsp_destroy_qp {
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

struct rsp_dealloc_uc {
	__u32 ctx_handle;
};

struct cmd_query_pkey {
	__u32 port;
	__u16 index;
};

struct rsp_query_pkey {
	__u16 pkey;
};

struct cmd_post_send {
	__u32 qpn;
	__u32 is_kernel;
	__u32 num_sge;

	int send_flags;
	enum ib_wr_opcode opcode;
	__u64 wr_id;

	union {
		__be32 imm_data;
		__u32 invalidate_rkey;
	} ex;
	
	union {
		struct {
			__u64 remote_addr;
			__u32 rkey;
		} rdma;
		struct {
			__u64 remote_addr;
			__u64 compare_add;
			__u64 swap;
			__u32 rkey;
		} atomic;
		struct {
			__u32 remote_qpn;
			__u32 remote_qkey;
			__u32 ahn;
		} ud;
		struct {
			__u32 mrn;
			__u32 key;
			int access;
		} reg;
	} wr;
};

struct cmd_post_recv {
	__u32 qpn;
	__u32 is_kernel;

	__u32 num_sge;
	__u64 wr_id;
};

#endif
