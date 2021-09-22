/*
 * Virtio RDMA device: IB related functions and data
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

#ifndef __VIRTIO_RDMA_IB__
#define __VIRTIO_RDMA_IB__

#include <linux/types.h>

#include <rdma/ib_verbs.h>
#include <uapi/rdma/virtio_rdma_abi.h>

enum virtio_rdma_type {
	VIRTIO_RDMA_TYPE_USER,
	VIRTIO_RDMA_TYPE_KERNEL
};

enum {
	VIRTIO_RDMA_ATOMIC_NONE,
	VIRTIO_RDMA_ATOMIC_HCA,
	VIRTIO_RDMA_ATOMIC_GLOB
};

static inline enum ib_atomic_cap virtio_rdma_atomic_cap_to_ib(uint32_t src) {
	switch (src) {
		case VIRTIO_RDMA_ATOMIC_NONE:
			return IB_ATOMIC_NONE;
		case VIRTIO_RDMA_ATOMIC_HCA:
			return IB_ATOMIC_HCA;
		case VIRTIO_RDMA_ATOMIC_GLOB:
			return IB_ATOMIC_GLOB;
		default:
			pr_warn("Unknown atomic cap");
	}
	return 0;
}

struct virtio_rdma_port_attr {
	enum ib_port_state	state;
	enum ib_mtu	 max_mtu;
	enum ib_mtu	 active_mtu;
	u32          phys_mtu;
	int			 gid_tbl_len;
	unsigned int ip_gids:1;
	u32			 port_cap_flags;
	u32          max_msg_sz;
	u32          bad_pkey_cntr;
	u32          qkey_viol_cntr;
	u16          pkey_tbl_len;
	u32          sm_lid;
	u32          lid;
	u8           lmc;
	u8           max_vl_num;
	u8           sm_sl;
	u8           subnet_timeout;
	u8           init_type_reply;
	u8           active_width;
	u16          active_speed;
	u8           phys_state;
	u16          port_cap_flags2;
};

struct virtio_rdma_pd {
	struct ib_pd ibpd;
	u32 pd_handle;
	enum virtio_rdma_type type;
};

struct virtio_rdma_mr {
	struct ib_mr ibmr;
	struct ib_umem *umem;

	u32 mr_handle;
	enum virtio_rdma_type type;
	u64 iova;
	u64 size;

	u64 *pages;
	dma_addr_t dma_pages;
	u32 npages;
	u32 max_pages;
};

struct virtio_rdma_vq {
	struct virtqueue* vq;
	spinlock_t lock;
	char name[16];
	int idx;
};

struct virtio_rdma_cq {
	struct ib_cq ibcq;
	u32 cq_handle;

	struct virtio_rdma_vq *vq;

	struct rdma_user_mmap_entry *entry;

	spinlock_t lock;
	struct virtio_rdma_cqe *queue;
	u32 num_cqe;
};

struct virtio_rdma_qp {
	struct ib_qp ibqp;
	u32 qp_handle;
	enum virtio_rdma_type type;
	u8 port;

	struct virtio_rdma_vq *sq;
	void* usq_buf;

	struct virtio_rdma_vq *rq;
	void* urq_buf;

	struct virtio_rdma_user_mmap_entry* entrys;
};

struct virtio_rdma_global_route {
	union ib_gid		dgid;
	uint32_t		flow_label;
	uint8_t			sgid_index;
	uint8_t			hop_limit;
	uint8_t			traffic_class;
};

struct virtio_rdma_ah_attr {
	struct virtio_rdma_global_route	grh;
	uint16_t			dlid;
	uint8_t				sl;
	uint8_t				src_path_bits;
	uint8_t				static_rate;
	uint8_t				port_num;
};

struct virtio_rdma_qp_cap {
	uint32_t		max_send_wr;
	uint32_t		max_recv_wr;
	uint32_t		max_send_sge;
	uint32_t		max_recv_sge;
	uint32_t		max_inline_data;
};

struct virtio_rdma_qp_attr {
	enum ib_qp_state	qp_state;
	enum ib_qp_state	cur_qp_state;
	enum ib_mtu		path_mtu;
	enum ib_mig_state	path_mig_state;
	uint32_t			qkey;
	uint32_t			rq_psn;
	uint32_t			sq_psn;
	uint32_t			dest_qp_num;
	uint32_t			qp_access_flags;
	uint16_t			pkey_index;
	uint16_t			alt_pkey_index;
	uint8_t			en_sqd_async_notify;
	uint8_t			sq_draining;
	uint8_t			max_rd_atomic;
	uint8_t			max_dest_rd_atomic;
	uint8_t			min_rnr_timer;
	uint8_t			port_num;
	uint8_t			timeout;
	uint8_t			retry_cnt;
	uint8_t			rnr_retry;
	uint8_t			alt_port_num;
	uint8_t			alt_timeout;
	uint32_t			rate_limit;
	struct virtio_rdma_qp_cap	cap;
	struct virtio_rdma_ah_attr	ah_attr;
	struct virtio_rdma_ah_attr	alt_ah_attr;
};

struct virtio_rdma_uar_map {
	unsigned long pfn;
	void __iomem *map;
	int index;
};

struct virtio_rdma_ucontext {
	struct ib_ucontext ibucontext;
	struct virtio_rdma_dev *dev;
	struct virtio_rdma_uar_map uar;
	__u64 ctx_handle;
};

struct virtio_rdma_av {
	__u32 port_pd;
	__u32 sl_tclass_flowlabel;
	__u8 dgid[16];
	__u8 src_path_bits;
	__u8 gid_index;
	__u8 stat_rate;
	__u8 hop_limit;
	__u8 dmac[6];
	__u8 reserved[6];
};

struct virtio_rdma_ah {
	struct ib_ah ibah;
	struct virtio_rdma_av av;
};

static inline struct virtio_rdma_ah *to_vah(struct ib_ah *ibah)
{
	return container_of(ibah, struct virtio_rdma_ah, ibah);
}

static inline struct virtio_rdma_pd *to_vpd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct virtio_rdma_pd, ibpd);
}

static inline struct virtio_rdma_cq *to_vcq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct virtio_rdma_cq, ibcq);
}

static inline struct virtio_rdma_qp *to_vqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct virtio_rdma_qp, ibqp);
}

static inline struct virtio_rdma_mr *to_vmr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct virtio_rdma_mr, ibmr);
}

static inline struct virtio_rdma_ucontext *to_vucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct virtio_rdma_ucontext, ibucontext);
}

int virtio_rdma_register_ib_device(struct virtio_rdma_dev *ri);
void virtio_rdma_unregister_ib_device(struct virtio_rdma_dev *ri);

#endif
