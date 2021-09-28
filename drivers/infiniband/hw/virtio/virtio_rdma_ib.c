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

#include <linux/scatterlist.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <rdma/ib_mad.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_addr.h>

#include "virtio_rdma.h"
#include "virtio_rdma_device.h"
#include "virtio_rdma_ib.h"
#include "virtio_rdma_dev_api.h"
#include "virtio_rdma_queue.h"
#include "virtio_rdma_loc.h"

#include "../../core/core_priv.h"

static const char* cmd_name[] = {
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
	[VIRTIO_CMD_QUERY_QP] = "VIRTIO_CMD_QUERY_QP",
    [VIRTIO_CMD_DESTROY_QP] = "VIRTIO_CMD_DESTROY_QP",
	[VIRTIO_CMD_QUERY_GID] = "VIRTIO_CMD_QUERY_GID",
	[VIRTIO_CMD_CREATE_UC] = "VIRTIO_CMD_CREATE_UC",
	[VIRTIO_CMD_DEALLOC_UC] = "VIRTIO_CMD_DEALLOC_UC",
	[VIRTIO_CMD_QUERY_PKEY] = "VIRTIO_CMD_QUERY_PKEY",
	[VIRTIO_CMD_ADD_GID] = "VIRTIO_CMD_ADD_GID",
	[VIRTIO_CMD_DEL_GID] = "VIRTIO_CMD_DEL_GID",
	[VIRTIO_CMD_REQ_NOTIFY_CQ] = "VIRTIO_CMD_REQ_NOTIFY_CQ",
};

static void ib_qp_cap_to_virtio_rdma(struct virtio_rdma_qp_cap *dst, const struct ib_qp_cap *src)
{
	dst->max_send_wr = src->max_send_wr;
	dst->max_recv_wr = src->max_recv_wr;
	dst->max_send_sge = src->max_send_sge;
	dst->max_recv_sge = src->max_recv_sge;
	dst->max_inline_data = src->max_inline_data;
}

static void virtio_rdma_to_ib_qp_cap(struct ib_qp_cap *dst, const struct virtio_rdma_qp_cap *src)
{
	dst->max_send_wr = src->max_send_wr;
	dst->max_recv_wr = src->max_recv_wr;
	dst->max_send_sge = src->max_send_sge;
	dst->max_recv_sge = src->max_recv_sge;
	dst->max_inline_data = src->max_inline_data;
}

void ib_global_route_to_virtio_rdma(struct virtio_rdma_global_route *dst,
			       const struct ib_global_route *src)
{
	dst->dgid = src->dgid;
	dst->flow_label = src->flow_label;
	dst->sgid_index = src->sgid_index;
	dst->hop_limit = src->hop_limit;
	dst->traffic_class = src->traffic_class;
}

void virtio_rdma_to_ib_global_route(struct ib_global_route *dst,
			       const struct virtio_rdma_global_route *src)
{
	dst->dgid = src->dgid;
	dst->flow_label = src->flow_label;
	dst->sgid_index = src->sgid_index;
	dst->hop_limit = src->hop_limit;
	dst->traffic_class = src->traffic_class;
}

void rdma_ah_attr_to_virtio_rdma(struct virtio_rdma_ah_attr *dst,
			    const struct rdma_ah_attr *src)
{
	ib_global_route_to_virtio_rdma(&dst->grh, rdma_ah_read_grh(src));
	// FIXME: this should be roce->dmac
	dst->dlid = rdma_ah_get_dlid(src);
	dst->sl = rdma_ah_get_sl(src);
	dst->src_path_bits = rdma_ah_get_path_bits(src);
	dst->static_rate = rdma_ah_get_static_rate(src);
	dst->port_num = rdma_ah_get_port_num(src);
}

void virtio_rdma_to_rdma_ah_attr(struct rdma_ah_attr *dst,
			    const struct virtio_rdma_ah_attr *src)
{
	virtio_rdma_to_ib_global_route(rdma_ah_retrieve_grh(dst), &src->grh);
	rdma_ah_set_dlid(dst, src->dlid);
	rdma_ah_set_sl(dst, src->sl);
	rdma_ah_set_path_bits(dst, src->src_path_bits);
	rdma_ah_set_static_rate(dst, src->static_rate);
	rdma_ah_set_port_num(dst, src->port_num);
}

static int virtio_rdma_exec_cmd(struct virtio_rdma_dev *di, int cmd,
				struct scatterlist *in, struct scatterlist *out)
{
	struct scatterlist *sgs[4], hdr, status;
	struct control_buf *ctrl;
	unsigned tmp;
	int rc, in_sgs = 1, out_sgs = 1;
	unsigned long flags;

	pr_info("%s: cmd %d %s\n", __func__, cmd, cmd_name[cmd]);
	spin_lock_irqsave(&di->ctrl_lock, flags);

	ctrl = kmalloc(sizeof(*ctrl), GFP_ATOMIC);
	ctrl->cmd = cmd;
	ctrl->status = ~0;

	sg_init_one(&hdr, &ctrl->cmd, sizeof(ctrl->cmd));
	sgs[0] = &hdr;
	if (in) {
		sgs[1] = in;
		in_sgs++;
	}
	sg_init_one(&status, &ctrl->status, sizeof(ctrl->status));
	sgs[in_sgs] = &status;
	if (out) {
		sgs[in_sgs + 1] = out;
		out_sgs++;
	}

	rc = virtqueue_add_sgs(di->ctrl_vq, sgs, in_sgs, out_sgs, di, GFP_ATOMIC);
	if (rc)
		goto out;

	if (unlikely(!virtqueue_kick(di->ctrl_vq))) {
		goto out_with_status;
	}

	while (!virtqueue_get_buf(di->ctrl_vq, &tmp) &&
	       !virtqueue_is_broken(di->ctrl_vq))
		cpu_relax();

out_with_status:
	pr_info("EXEC cmd %d %s, status %d\n", ctrl->cmd, cmd_name[ctrl->cmd], ctrl->status);
	rc = ctrl->status == VIRTIO_RDMA_CTRL_OK ? 0 : 1;

out:
	spin_unlock_irqrestore(&di->ctrl_lock, flags);
	kfree(ctrl);
	return rc;
}

static struct scatterlist* init_sg(void* buf, unsigned long nbytes) {
	struct scatterlist* sg;

	if (is_vmalloc_addr(buf)) {
		int num_page = 1;
		int i, off;
		unsigned int len = nbytes;
		// pr_info("vmalloc address %px\n", buf);

		off = offset_in_page(buf);
		if (off + nbytes > (int)PAGE_SIZE) {
			num_page += (nbytes + off - PAGE_SIZE) / PAGE_SIZE;
			len = PAGE_SIZE - off;
		}

		sg = kmalloc(sizeof(*sg) * num_page, GFP_ATOMIC);
		if (!sg)
			return NULL;

		sg_init_table(sg, num_page);

		for (i = 0; i < num_page; i++)	{
			sg_set_page(sg + i, vmalloc_to_page(buf), len, off);

			nbytes -= len;
			buf += len;
			off = 0;
			len = min(nbytes, PAGE_SIZE);
		}
	} else {
		sg = kmalloc(sizeof(*sg), GFP_ATOMIC);
		if (!sg)
			return NULL;
        sg_init_one(sg, buf, nbytes);
	}

	return sg;
}

static int virtio_rdma_port_immutable(struct ib_device *ibdev, u32 port_num,
				      struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int rc;

	rc = ib_query_port(ibdev, port_num, &attr);
	if (rc)
		return rc;

	immutable->core_cap_flags = RDMA_CORE_PORT_VIRTIO;
	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

static int virtio_rdma_query_device(struct ib_device *ibdev,
				    struct ib_device_attr *props,
				    struct ib_udata *uhw)
{
	if (uhw->inlen || uhw->outlen)
		return -EINVAL;

	*props = to_vdev(ibdev)->attr;
	return 0;
}

static int virtio_rdma_query_port(struct ib_device *ibdev, u32 port,
				  struct ib_port_attr *props)
{
	struct scatterlist in, *out;
	struct cmd_query_port *cmd;
	struct virtio_rdma_port_attr port_attr;
	int rc;

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	out = init_sg(&port_attr, sizeof(port_attr));
	if (!out) {
		kfree(cmd);
		return -ENOMEM;
	}

	cmd->port = port;
	sg_init_one(&in, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(to_vdev(ibdev), VIRTIO_CMD_QUERY_PORT, &in,
				  out);

	props->state = port_attr.state;
	props->max_mtu = port_attr.max_mtu;
	props->active_width = port_attr.active_width;
	props->phys_mtu = port_attr.phys_mtu;
	props->gid_tbl_len = port_attr.gid_tbl_len;
	props->ip_gids = port_attr.ip_gids;
	props->port_cap_flags = port_attr.port_cap_flags;
	props->max_msg_sz = port_attr.max_msg_sz;
	props->bad_pkey_cntr = port_attr.bad_pkey_cntr;
	props->qkey_viol_cntr = port_attr.qkey_viol_cntr;
	props->pkey_tbl_len = port_attr.pkey_tbl_len;
	props->sm_lid = port_attr.sm_lid;
	props->lid = port_attr.lid;
	props->lmc = port_attr.lmc;
	props->max_vl_num = port_attr.max_vl_num;
	props->sm_sl = port_attr.sm_sl;
	props->subnet_timeout = port_attr.subnet_timeout;
	props->init_type_reply = port_attr.init_type_reply;
	props->active_width = port_attr.active_width;
	props->active_speed = port_attr.active_speed;
	props->phys_state = port_attr.phys_state;
	props->port_cap_flags2 = port_attr.port_cap_flags2;

	kfree(out);
	kfree(cmd);

	return rc;
}

static struct net_device *virtio_rdma_get_netdev(struct ib_device *ibdev,
						 u32 port_num)
{
	struct virtio_rdma_dev *ri = to_vdev(ibdev);
	return ri->netdev;
}

static int virtio_rdma_create_cq(struct ib_cq *ibcq,
				    const struct ib_cq_init_attr *attr,
				    struct ib_udata *udata)
{
	struct scatterlist in, out;
	struct virtio_rdma_cq *vcq = to_vcq(ibcq);
	struct virtio_rdma_dev *vdev = to_vdev(ibcq->device);
	struct cmd_create_cq *cmd;
	struct rsp_create_cq *rsp;
	struct scatterlist sg;
	int rc, i;
	int entries = attr->cqe;
	int total_size;
	struct virtio_rdma_user_mmap_entry* entry;

	if (!atomic_add_unless(&vdev->num_cq, 1, ibcq->device->attrs.max_cq))
		return -ENOMEM;

	total_size = PAGE_ALIGN(entries * sizeof(*vcq->queue));
	vcq->queue = alloc_pages_exact(total_size, GFP_KERNEL);
	if (!vcq->queue)
		return -ENOMEM;

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd) {
		kfree(vcq->queue);
		return -ENOMEM;
	}

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp) {
		kfree(vcq->queue);
		kfree(cmd);
		return -ENOMEM;
	}
	
	if (udata) {
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (!entry) {
			kfree(vcq->queue);
			kfree(cmd);
			kfree(rsp);
			return -ENOMEM;
		}
	}

	cmd->cqe = attr->cqe;
	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(vdev, VIRTIO_CMD_CREATE_CQ, &in,
				  &out);
	if (rc) {
		kfree(vcq->queue);
		goto out;
	}

	vcq->cq_handle = rsp->cqn;
	vcq->ibcq.cqe = entries;
	vcq->vq = &vdev->cq_vqs[rsp->cqn];
	vcq->num_cqe = entries;
	vdev->cqs[rsp->cqn] = vcq;

	if (udata) {
		struct virtio_rdma_create_cq_uresp uresp = {};
		struct virtio_rdma_ucontext *uctx = rdma_udata_to_drv_context(udata,
			struct virtio_rdma_ucontext, ibucontext);

		entry->type = VIRTIO_RDMA_MMAP_CQ;
		entry->queue = vcq->vq->vq;
		entry->ubuf = vcq->queue;
		entry->ubuf_size = total_size;

		uresp.vq_align = SMP_CACHE_BYTES;
		uresp.vq_size = PAGE_ALIGN(vring_size(virtqueue_get_vring_size(vcq->vq->vq), SMP_CACHE_BYTES));
		total_size += uresp.vq_size;

		rc = rdma_user_mmap_entry_insert(&uctx->ibucontext, &entry->rdma_entry,
			total_size);
		if (rc)
			goto out_err;

		uresp.offset = rdma_user_mmap_get_offset(&entry->rdma_entry);
		uresp.cq_phys_addr = virt_to_phys(vcq->queue);
		uresp.num_cqe = entries;
		uresp.num_cvqe = virtqueue_get_vring_size(vcq->vq->vq);
		uresp.cq_size = total_size;

		if (udata->outlen < sizeof(uresp)) {
			rc = -EINVAL;
			goto out_err;
		}
		rc = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rc)
			goto out_err;

		vcq->entry = &entry->rdma_entry;
	} else {
		for(i = 0; i < entries; i++) {
			sg_init_one(&sg, vcq->queue + i, sizeof(*vcq->queue));
			virtqueue_add_inbuf(vcq->vq->vq, &sg, 1, vcq->queue + i, GFP_KERNEL);
		}
	}

	spin_lock_init(&vcq->lock);

	goto out;

out_err:
	if (entry)
		kfree(entry);
	kfree(vcq->queue);
out:
	kfree(rsp);
	kfree(cmd);
	return rc;
}

static int virtio_rdma_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
{
	struct virtio_rdma_cq *vcq;
	struct scatterlist in;
	struct cmd_destroy_cq *cmd;

	unsigned tmp;

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	vcq = to_vcq(cq);

	cmd->cqn = vcq->cq_handle;
	sg_init_one(&in, cmd, sizeof(*cmd));

	virtqueue_disable_cb(vcq->vq->vq);

	virtio_rdma_exec_cmd(to_vdev(cq->device), VIRTIO_CMD_DESTROY_CQ,
				  &in, NULL);

	/* pop all from virtqueue, after host call virtqueue_drop_all,
	 * prepare for next use.
	 */
	if (!udata)
		while(virtqueue_get_buf(vcq->vq->vq, &tmp));

	atomic_dec(&to_vdev(cq->device)->num_cq);
	virtqueue_enable_cb(vcq->vq->vq);

	if (vcq->entry)
		rdma_user_mmap_entry_remove(vcq->entry);

	to_vdev(cq->device)->cqs[vcq->cq_handle] = NULL;

	kfree(vcq->queue);
	kfree(cmd);
	return 0;
}

static int virtio_rdma_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct virtio_rdma_pd *pd = to_vpd(ibpd);
	struct ib_device *ibdev = ibpd->device;
	struct cmd_create_pd *cmd;
	struct rsp_create_pd *rsp;
	struct scatterlist out, in;
	int rc;
	struct virtio_rdma_ucontext *context = rdma_udata_to_drv_context(
		udata, struct virtio_rdma_ucontext, ibucontext);

	// TODO: Check MAX_PD
	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp) {
		kfree(cmd);
		return -ENOMEM;
	}

	cmd->ctx_handle = context ? context->ctx_handle : 0;
	sg_init_one(&in, cmd, sizeof(*cmd));

	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(ibdev), VIRTIO_CMD_CREATE_PD, &in,
				  &out);
	if (rc)
		goto out;

	pd->pd_handle = rsp->pdn;

	printk("%s: pd_handle=%d\n", __func__, pd->pd_handle);

out:
	kfree(rsp);
	kfree(cmd);

	printk("%s: rc=%d\n", __func__, rc);
	return rc;
}

static int virtio_rdma_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct virtio_rdma_pd *vpd = to_vpd(pd);
	struct ib_device *ibdev = pd->device;
	struct cmd_destroy_pd *cmd;
	struct scatterlist in;

	pr_debug("%s:\n", __func__);

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	cmd->pdn = vpd->pd_handle;
	sg_init_one(&in, cmd, sizeof(*cmd));

	virtio_rdma_exec_cmd(to_vdev(ibdev), VIRTIO_CMD_DESTROY_PD, &in, NULL);

	kfree(cmd);
	return 0;
}

struct ib_mr *virtio_rdma_get_dma_mr(struct ib_pd *pd, int flags)
{
	struct virtio_rdma_mr *mr;
	struct scatterlist in, out;
	struct cmd_create_mr *cmd;
	struct rsp_create_mr *rsp;
	int rc;

	mr = kzalloc(sizeof(*mr), GFP_ATOMIC);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd) {
		kfree(mr);
		return ERR_PTR(-ENOMEM);
	}

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!cmd) {
		kfree(mr);
		kfree(cmd);
		return ERR_PTR(-ENOMEM);
	}

	cmd->pdn = to_vpd(pd)->pd_handle;
	cmd->access_flags = flags;
	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));

	pr_warn("Not support DMA mr now\n");

	rc = virtio_rdma_exec_cmd(to_vdev(pd->device), VIRTIO_CMD_GET_DMA_MR,
				  &in, &out);
	pr_info("%s: mr_handle=0x%x\n", __func__, rsp->mrn);
	if (rc) {
		kfree(rsp);
		kfree(mr);
		kfree(cmd);
		return ERR_PTR(rc);
	}

	mr->mr_handle = rsp->mrn;
	mr->ibmr.lkey = rsp->lkey;
	mr->ibmr.rkey = rsp->rkey;
	mr->type = VIRTIO_RDMA_TYPE_KERNEL;
	to_vpd(pd)->type = VIRTIO_RDMA_TYPE_KERNEL;

	kfree(cmd);
	kfree(rsp);

	return &mr->ibmr;
}

static struct ib_mr *virtio_rdma_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
				   u32 max_num_sg)
{
	struct virtio_rdma_dev *dev = to_vdev(pd->device);
	struct virtio_rdma_pd *vpd = to_vpd(pd);
	struct virtio_rdma_mr *mr;
	struct scatterlist in, out;
	struct cmd_create_mr *cmd;
	struct rsp_create_mr *rsp;
	struct ib_mr *ret = ERR_PTR(-ENOMEM);
	int rc;

	pr_info("%s: mr_type %d, max_num_sg %d\n", __func__, mr_type,
	       max_num_sg);

	if (mr_type != IB_MR_TYPE_MEM_REG)
		return ERR_PTR(-EINVAL);

	mr = kzalloc(sizeof(*mr), GFP_ATOMIC);
	if (!mr)
		goto err;

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		goto err_cmd;

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!cmd)
		goto err_rsp;

	 // FIXME: only support PAGE_SIZE/8 sg;
	mr->pages = dma_alloc_coherent(dev->vdev->dev.parent, PAGE_SIZE, &mr->dma_pages, GFP_KERNEL);
	if (!mr->pages) {
		pr_err("dma alloc pages failed\n");
		goto err_pages;
	}
	mr->max_pages = max_num_sg;
	mr->npages = 0;

	memset(cmd, 0, sizeof(*cmd));
	cmd->pdn = to_vpd(pd)->pd_handle;
	cmd->max_num_sg = max_num_sg;

	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(pd->device), VIRTIO_CMD_CREATE_MR,
				  &in, &out);

	if (rc) {
		kfree(rsp);
		kfree(mr);
		kfree(cmd);
		return ERR_PTR(rc);
	}

	mr->mr_handle = rsp->mrn;
	mr->ibmr.lkey = rsp->lkey;
	mr->ibmr.rkey = rsp->rkey;
	mr->type = VIRTIO_RDMA_TYPE_KERNEL;
	vpd->type = VIRTIO_RDMA_TYPE_KERNEL;

	pr_info("%s: mr_handle=0x%x\n", __func__, mr->mr_handle);

	kfree(cmd);
	kfree(rsp);

	return &mr->ibmr;

err_pages:
	kfree(rsp);
err_rsp:
	kfree(cmd);
err_cmd:
	kfree(mr);
err:
	return ret;
}

static int virtio_rdma_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct virtio_rdma_mr *mr = to_vmr(ibmr);

	if (mr->npages == mr->max_pages)
		return -ENOMEM;

	if (is_vmalloc_addr((void*)addr)) {
		pr_err("vmalloc addr is not support\n");
		return -EINVAL;
	}
	mr->pages[mr->npages++] = virt_to_phys((void*)addr);
	return 0;
}

int virtio_rdma_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
			  int sg_nents, unsigned int *sg_offset)
{
	struct virtio_rdma_mr *mr = to_vmr(ibmr);
	struct cmd_map_mr_sg *cmd;
	struct rsp_map_mr_sg *rsp;
	struct scatterlist in, out;
	int rc;

	cmd = kmalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;
	rsp = kmalloc(sizeof(*rsp), GFP_KERNEL);
	if (!rsp) {
		rc = -ENOMEM;
		goto out_rsp;
	}

	mr->npages = 0;

	rc = ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, virtio_rdma_set_page);
	if (rc < 0) {
		pr_err("could not map sg to pages\n");
		rc = -EINVAL;
		goto out;
	}

	pr_info("%s: start %llx npages %d\n", __func__, sg[0].dma_address, mr->npages);

	cmd->mrn = mr->mr_handle;
	cmd->start = (uint64_t)phys_to_virt(mr->pages[0]);
	cmd->npages = mr->npages;
	cmd->pages = mr->dma_pages;

	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(ibmr->device), VIRTIO_CMD_MAP_MR_SG,
				  &in, &out);

	if (rc)
		rc = -EIO;

out:
	kfree(rsp);
out_rsp:
	kfree(cmd);
	return rc;
}

struct ib_mr *virtio_rdma_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				      u64 virt_addr, int access_flags,
				      struct ib_udata *udata)
{
	struct virtio_rdma_dev *dev = to_vdev(pd->device);
	struct virtio_rdma_pd *vpd = to_vpd(pd);
	struct virtio_rdma_mr *mr;
	struct ib_umem *umem;
	struct ib_mr *ret = ERR_PTR(-ENOMEM);
	struct sg_dma_page_iter sg_iter;
	struct scatterlist in, out;
	struct cmd_reg_user_mr *cmd;
	struct rsp_reg_user_mr *rsp;
	int rc;
	uint32_t npages;

	pr_info("%s: start %llx, len %llu, addr %llx\n", __func__, start, length,
	        virt_addr);

	umem = ib_umem_get(pd->device, start, length, access_flags);
	if (IS_ERR(umem)) {
		pr_err("could not get umem for mem region\n");
		ret = ERR_CAST(umem);
		goto out;
	}

	npages = ib_umem_num_pages(umem);
	if (npages < 0) {
		pr_err("npages < 0");
		ret = ERR_PTR(-EINVAL);
		goto out;
	}

	pr_info("npages = %u\n", npages);

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd) 
		return ERR_PTR(-ENOMEM);

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp)
		goto err_rsp;

	mr = kzalloc(sizeof(*mr), GFP_ATOMIC);
	if (!mr) {
		ret = ERR_PTR(-ENOMEM);
		goto err;
	}

	// TODO: change page size to needed
	mr->pages = dma_alloc_coherent(dev->vdev->dev.parent, PAGE_SIZE, &mr->dma_pages, GFP_KERNEL);
	if (!mr->pages) {
		pr_err("dma alloc pages failed\n");
		goto err;
	}

	mr->max_pages = npages;
	mr->iova = virt_addr;
	mr->size = length;
	mr->umem = umem;

	// TODO: test pages
	mr->npages = 0;
	for_each_sg_dma_page(umem->sg_head.sgl, &sg_iter, umem->nmap, 0) {
		dma_addr_t addr = sg_page_iter_dma_address(&sg_iter);
		mr->pages[mr->npages] = virt_to_phys((void*)addr);
		pr_info("set page %llx", addr);
		mr->npages++;
	}

	cmd->pdn = to_vpd(pd)->pd_handle;
	cmd->access_flags = access_flags;
	cmd->start = start;
	cmd->length = length;
	cmd->virt_addr = virt_addr;
	cmd->pages = mr->dma_pages;
	cmd->npages = npages;

	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(pd->device), VIRTIO_CMD_REG_USER_MR,
				  &in, &out);

	if (rc) {
		ib_umem_release(umem);
		kfree(rsp);
		kfree(mr);
		kfree(cmd);
		return ERR_PTR(rc);
	}

	mr->mr_handle = rsp->mrn;
	mr->ibmr.lkey = rsp->lkey;
	mr->ibmr.rkey = rsp->rkey;
	mr->type = VIRTIO_RDMA_TYPE_USER;
	vpd->type = VIRTIO_RDMA_TYPE_USER;

	printk("%s: mr_handle=0x%x\n", __func__, mr->mr_handle);

	ret = &mr->ibmr;

err:
	kfree(cmd);
err_rsp:
	kfree(rsp);
out:
	return ret;
}

int virtio_rdma_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct virtio_rdma_mr *mr = to_vmr(ibmr);
	struct scatterlist in;
	struct cmd_dereg_mr *cmd;
	int rc = -ENOMEM;

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	cmd->mrn = mr->mr_handle;
	cmd->is_user_mr = mr->type == VIRTIO_RDMA_TYPE_USER;

	sg_init_one(&in, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(to_vdev(ibmr->device), VIRTIO_CMD_DEREG_MR,
	                          &in, NULL);
	if (rc) {
		rc = -EIO;
		goto out;
	}

	dma_free_coherent(to_vdev(ibmr->device)->vdev->dev.parent, PAGE_SIZE, &mr->pages, GFP_KERNEL);
	if (mr->type == VIRTIO_RDMA_TYPE_USER)
		ib_umem_release(mr->umem);

out:
	kfree(cmd);
	return rc;
}

static int find_qp_vq(struct virtio_rdma_dev *dev, uint32_t qpn) {
	int rc = -1, i;
	unsigned long flags;
	uint32_t max_qp = dev->ib_dev.attrs.max_qp;

	spin_lock_irqsave(&dev->qp_using_lock, flags);
	for(i = 0; i < max_qp; i++) {
		if (dev->qp_vq_using[i] == -1) {
			rc = i;
			dev->qp_vq_using[i] = qpn;
			goto found;
		}
	}
found:
	spin_unlock_irqrestore(&dev->qp_using_lock, flags);
	return rc;
}

static void* virtio_rdma_init_mmap_entry(struct virtqueue *vq,
           struct virtio_rdma_user_mmap_entry** entry_, int buf_size,
		   struct virtio_rdma_ucontext* vctx, __u64* size, __u32* vq_size)
{
	void* buf = NULL;
	int rc;
	size_t total_size;
	struct virtio_rdma_user_mmap_entry* entry;

	total_size = PAGE_ALIGN(buf_size);
	buf = alloc_pages_exact(total_size, GFP_KERNEL);
	if (!buf)
		return NULL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		kfree(buf);
		return NULL;
	}

	entry->type = VIRTIO_RDMA_MMAP_QP;
	entry->queue = vq;
	entry->ubuf = buf;
	entry->ubuf_size = PAGE_ALIGN(buf_size);

	*vq_size = PAGE_ALIGN(vring_size(virtqueue_get_vring_size(vq), SMP_CACHE_BYTES));
	total_size += *vq_size + PAGE_SIZE;

	rc = rdma_user_mmap_entry_insert(&vctx->ibucontext, &entry->rdma_entry,
			total_size);
	if (rc) {
		kfree(buf);
		return NULL;
	}

	*size = total_size;
	*entry_ = entry;
	return buf;
}

struct ib_qp *virtio_rdma_create_qp(struct ib_pd *ibpd,
				    struct ib_qp_init_attr *attr,
				    struct ib_udata *udata)
{
	struct scatterlist in, out;
	struct virtio_rdma_dev *vdev = to_vdev(ibpd->device);
	struct virtio_rdma_pd *vpd = to_vpd(ibpd);
	struct cmd_create_qp *cmd;
	struct rsp_create_qp *rsp;
	struct virtio_rdma_qp *vqp;
	int rc, vqn;
	struct ib_qp *ret;

	if (!atomic_add_unless(&vdev->num_qp, 1, vdev->ib_dev.attrs.max_qp))
        return ERR_PTR(-ENOMEM);

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return ERR_PTR(-ENOMEM);

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp) {
		kfree(cmd);
		return ERR_PTR(-ENOMEM);
	}

	vqp = kzalloc(sizeof(*vqp), GFP_ATOMIC);
	if (!vqp) {
		kfree(cmd);
		kfree(rsp);
		return ERR_PTR(-ENOMEM);
	}

	cmd->pdn = to_vpd(ibpd)->pd_handle;
	cmd->qp_type = attr->qp_type;
	cmd->max_send_wr = attr->cap.max_send_wr;
	cmd->max_send_sge = attr->cap.max_send_sge;
	cmd->send_cqn = to_vcq(attr->send_cq)->cq_handle;
	cmd->max_recv_wr = attr->cap.max_recv_wr;
	cmd->max_recv_sge = attr->cap.max_recv_sge;
	cmd->recv_cqn = to_vcq(attr->recv_cq)->cq_handle;
	cmd->is_srq = !!attr->srq;
	cmd->srq_handle = 0; // Not support srq now

	sg_init_one(&in, cmd, sizeof(*cmd));
	printk("%s: pdn %d\n", __func__, cmd->pdn);

	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(vdev, VIRTIO_CMD_CREATE_QP, &in,
				  &out);
	if (rc) {
		ret = ERR_PTR(-EIO);
		goto out_err;
	}

	vqp->type = vpd->type;
	vqp->port = attr->port_num;
	vqp->qp_handle = rsp->qpn;
	vqp->ibqp.qp_num = rsp->qpn;

	vqn = find_qp_vq(vdev, vqp->qp_handle);
	vqp->sq = &vdev->qp_vqs[vqn * 2];
	vqp->rq = &vdev->qp_vqs[vqn * 2 + 1];

	if (udata) {
		struct virtio_rdma_create_qp_uresp uresp = {};
		struct virtio_rdma_ucontext *uctx = rdma_udata_to_drv_context(udata,
			struct virtio_rdma_ucontext, ibucontext);
		uint32_t per_size;
		
		per_size = sizeof(struct virtio_rdma_cmd_post_send) +
				   sizeof(struct virtio_rdma_sge) * attr->cap.max_send_sge;
		vqp->usq_buf = virtio_rdma_init_mmap_entry(vqp->sq->vq, &vqp->sq_entry,
				per_size * attr->cap.max_send_wr, uctx, &uresp.sq_size,
				&uresp.svq_size);
		if (!vqp->usq_buf)
			goto out_err;

		per_size = sizeof(struct virtio_rdma_cmd_post_recv) +
				   sizeof(struct virtio_rdma_sge) * attr->cap.max_recv_sge;
		vqp->urq_buf = virtio_rdma_init_mmap_entry(vqp->rq->vq, &vqp->rq_entry,
				per_size * attr->cap.max_recv_wr, uctx, &uresp.rq_size,
				&uresp.rvq_size);
		if (!vqp->urq_buf) {
			// TODO: pop sq entry
			kfree(vqp->usq_buf);
			goto out_err;
		}

		uresp.sq_offset = rdma_user_mmap_get_offset(&vqp->sq_entry->rdma_entry);
		uresp.sq_phys_addr = virt_to_phys(vqp->usq_buf);
		uresp.num_sqe = attr->cap.max_send_wr;
		uresp.num_svqe = virtqueue_get_vring_size(vqp->sq->vq);
		uresp.sq_idx = vqp->sq->vq->index;

		uresp.rq_offset = rdma_user_mmap_get_offset(&vqp->rq_entry->rdma_entry);
		uresp.rq_phys_addr = virt_to_phys(vqp->urq_buf);
		uresp.num_rqe = attr->cap.max_recv_wr;
		uresp.num_rvqe = virtqueue_get_vring_size(vqp->rq->vq);
		uresp.rq_idx = vqp->rq->vq->index;

		uresp.vq_align = SMP_CACHE_BYTES;
		uresp.page_size = PAGE_SIZE;
		uresp.qpn = vqp->qp_handle;

		if (udata->outlen < sizeof(uresp)) {
			rc = -EINVAL;
			goto out_err_u;
		}
		rc = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rc)
			goto out_err_u;
	}

	pr_info("%s: qpn 0x%x wq %d rq %d\n", __func__, rsp->qpn,
	        vqp->sq->vq->index, vqp->rq->vq->index);
	ret = &vqp->ibqp;
	goto out;

out_err_u:
	kfree(vqp->usq_buf);
	kfree(vqp->urq_buf);
	rdma_user_mmap_entry_remove(&vqp->sq_entry->rdma_entry);
	rdma_user_mmap_entry_remove(&vqp->rq_entry->rdma_entry);
out_err:
	kfree(vqp);
out:
	kfree(rsp);
	kfree(cmd);
	return ret;
}

int virtio_rdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct virtio_rdma_dev *vdev = to_vdev(ibqp->device);
	struct virtio_rdma_qp *vqp = to_vqp(ibqp);
	struct scatterlist in;
	struct cmd_destroy_qp *cmd;
	int rc;

	pr_info("%s: qpn %d\n", __func__, vqp->qp_handle);

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	cmd->qpn = vqp->qp_handle;

	sg_init_one(&in, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(vdev, VIRTIO_CMD_DESTROY_QP,
	                          &in, NULL);

	if (udata) {
		kfree(vqp->usq_buf);
		kfree(vqp->urq_buf);
		rdma_user_mmap_entry_remove(&vqp->sq_entry->rdma_entry);
		rdma_user_mmap_entry_remove(&vqp->rq_entry->rdma_entry);
	}

	atomic_dec(&vdev->num_qp);

	smp_store_mb(vdev->qp_vq_using[vqp->sq->idx / 2], -1);

	kfree(cmd);
	return rc;
}

int virtio_rdma_query_gid(struct ib_device *ibdev, u32 port, int index,
			  union ib_gid *gid)
{
	struct scatterlist in, *data;
	struct cmd_query_gid *cmd;
	struct ib_gid_attr gid_attr;
	int rc;

	printk("%s: port %d, index %d\n", __func__, port, index);

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	data = init_sg(gid, sizeof(*gid));
	if (!data) {
		kfree(cmd);
		return -ENOMEM;
	}

	cmd->port = port;
	cmd->index = index;
	sg_init_one(&in, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(to_vdev(ibdev), VIRTIO_CMD_QUERY_GID, &in,
				  data);

	if (!rc) {
		gid_attr.ndev = to_vdev(ibdev)->netdev;
		gid_attr.gid_type = IB_GID_TYPE_ROCE_UDP_ENCAP;
		ib_cache_gid_add(ibdev, port, gid, &gid_attr);
	}

	kfree(data);
	kfree(cmd);
	return rc;
}

static int virtio_rdma_add_gid(const struct ib_gid_attr *attr, void **context)
{
	printk("%s: gid index %d\n", __func__, attr->index);

	return 0;
}

static int virtio_rdma_del_gid(const struct ib_gid_attr *attr, void **context)
{
	printk("%s:\n", __func__);

	return 0;
}

int virtio_rdma_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata)
{
	struct scatterlist in, out;
	struct cmd_create_uc *cmd;
	struct rsp_create_uc *rsp;
	struct virtio_rdma_ucontext *vuc = to_vucontext(uctx);
	int rc;
	
	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp) {
		kfree(cmd);
		return -ENOMEM;
	}

	// TODO: init uar & set cmd->pfn
	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(uctx->device), VIRTIO_CMD_CREATE_UC, &in,
				  &out);

	if (rc) {
		rc = -EIO;
		goto out;
	}

	vuc->ctx_handle = rsp->ctx_handle;

out:
	kfree(rsp);
	kfree(cmd);
	return rc;
}

static void virtio_rdma_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	struct scatterlist in;
	struct cmd_dealloc_uc *cmd;
	struct virtio_rdma_ucontext *vuc = to_vucontext(ibcontext);
	
	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return;

	cmd->ctx_handle = vuc->ctx_handle;
	sg_init_one(&in, cmd, sizeof(*cmd));

	virtio_rdma_exec_cmd(to_vdev(ibcontext->device), VIRTIO_CMD_DEALLOC_UC, &in,
				  NULL);

	kfree(cmd);
}

static int virtio_rdma_create_ah(struct ib_ah *ibah,
				    struct rdma_ah_init_attr *init_attr,
				    struct ib_udata *udata)
{
	struct virtio_rdma_dev *vdev = to_vdev(ibah->device);
	struct virtio_rdma_ah *ah = to_vah(ibah);
	const struct ib_global_route *grh;
	u32 port_num = rdma_ah_get_port_num(init_attr->ah_attr);

	if (!(rdma_ah_get_ah_flags(init_attr->ah_attr) & IB_AH_GRH))
		return -EINVAL;

	grh = rdma_ah_read_grh(init_attr->ah_attr);
	if ((init_attr->ah_attr->type != RDMA_AH_ATTR_TYPE_ROCE)  ||
	    rdma_is_multicast_addr((struct in6_addr *)grh->dgid.raw))
		return -EINVAL;

	if (!atomic_add_unless(&vdev->num_ah, 1, vdev->ib_dev.attrs.max_ah))
		return -ENOMEM;

	ah->av.port_pd = to_vpd(ibah->pd)->pd_handle | (port_num << 24);
	ah->av.src_path_bits = rdma_ah_get_path_bits(init_attr->ah_attr);
	ah->av.src_path_bits |= 0x80;
	ah->av.gid_index = grh->sgid_index;
	ah->av.hop_limit = grh->hop_limit;
	ah->av.sl_tclass_flowlabel = (grh->traffic_class << 20) |
				      grh->flow_label;
	memcpy(ah->av.dgid, grh->dgid.raw, 16);
	memcpy(ah->av.dmac, init_attr->ah_attr->roce.dmac, ETH_ALEN);

	return 0;
}

static int virtio_rdma_destroy_ah(struct ib_ah *ah, u32 flags)
{
	struct virtio_rdma_dev *vdev = to_vdev(ah->device);

	printk("%s:\n", __func__);
	atomic_dec(&vdev->num_ah);

	return 0;
}

static void virtio_rdma_get_fw_ver_str(struct ib_device *device, char *str)
{
	snprintf(str, IB_FW_VERSION_NAME_MAX, "%d.%d.%d\n", 1, 0, 0);
}

static enum rdma_link_layer virtio_rdma_port_link_layer(struct ib_device *ibdev,
						 u32 port)
{
	return IB_LINK_LAYER_ETHERNET;
}

static int virtio_rdma_modify_port(struct ib_device *ibdev, u32 port, int mask,
			    struct ib_port_modify *props)
{
	struct ib_port_attr attr;
	struct virtio_rdma_dev *vdev = to_vdev(ibdev);
	int ret;

	if (mask & ~IB_PORT_SHUTDOWN) {
		pr_warn("unsupported port modify mask %#x\n", mask);
		return -EOPNOTSUPP;
	}

	mutex_lock(&vdev->port_mutex);
	ret = ib_query_port(ibdev, port, &attr);
	if (ret)
		goto out;

	vdev->port_cap_mask |= props->set_port_cap_mask;
	vdev->port_cap_mask &= ~props->clr_port_cap_mask;

	if (mask & IB_PORT_SHUTDOWN)
		vdev->ib_active = false;

out:
	mutex_unlock(&vdev->port_mutex);
	return ret;
}

int virtio_rdma_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			  int attr_mask, struct ib_udata *udata)
{
	struct scatterlist in, out;
	struct cmd_modify_qp *cmd;
	struct rsp_modify_qp *rsp;
	int rc;

	pr_info("%s: qpn %d\n", __func__, to_vqp(ibqp)->qp_handle);

	cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp) {
		kfree(cmd);
		return -ENOMEM;
	}

	cmd->qpn = to_vqp(ibqp)->qp_handle;
	cmd->attr_mask = attr_mask & ((1 << 21) - 1);

	// TODO: copy based on attr_mask
	cmd->attrs.qp_state = attr->qp_state;
	cmd->attrs.cur_qp_state = attr->cur_qp_state;
	cmd->attrs.path_mtu = attr->path_mtu;
	cmd->attrs.path_mig_state = attr->path_mig_state;
	cmd->attrs.qkey = attr->qkey;
	cmd->attrs.rq_psn = attr->rq_psn;
	cmd->attrs.sq_psn = attr->sq_psn;
	cmd->attrs.dest_qp_num = attr->dest_qp_num;
	cmd->attrs.qp_access_flags = attr->qp_access_flags;
	cmd->attrs.pkey_index = attr->pkey_index;
	cmd->attrs.alt_pkey_index = attr->alt_pkey_index;
	cmd->attrs.en_sqd_async_notify = attr->en_sqd_async_notify;
	cmd->attrs.sq_draining = attr->sq_draining;
	cmd->attrs.max_rd_atomic = attr->max_rd_atomic;
	cmd->attrs.max_dest_rd_atomic = attr->max_dest_rd_atomic;
	cmd->attrs.min_rnr_timer = attr->min_rnr_timer;
	cmd->attrs.port_num = attr->port_num;
	cmd->attrs.timeout = attr->timeout;
	cmd->attrs.retry_cnt = attr->retry_cnt;
	cmd->attrs.rnr_retry = attr->rnr_retry;
	cmd->attrs.alt_port_num = attr->alt_port_num;
	cmd->attrs.alt_timeout = attr->alt_timeout;
	cmd->attrs.rate_limit = attr->rate_limit;
	ib_qp_cap_to_virtio_rdma(&cmd->attrs.cap, &attr->cap);
	rdma_ah_attr_to_virtio_rdma(&cmd->attrs.ah_attr, &attr->ah_attr);
	rdma_ah_attr_to_virtio_rdma(&cmd->attrs.alt_ah_attr, &attr->alt_ah_attr);

	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(ibqp->device), VIRTIO_CMD_MODIFY_QP,
	                          &in, &out);

	kfree(rsp);
	kfree(cmd);
	return rc;
}

int virtio_rdma_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int attr_mask, struct ib_qp_init_attr *init_attr)
{
	struct scatterlist in, out;
	struct virtio_rdma_qp *vqp = to_vqp(ibqp);
	struct cmd_query_qp *cmd;
	struct rsp_query_qp *rsp;
	int rc;

	cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp) {
		kfree(cmd);
		return -ENOMEM;
	}

	cmd->qpn = vqp->qp_handle;
	cmd->attr_mask = attr_mask;

	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));
	rc = virtio_rdma_exec_cmd(to_vdev(ibqp->device), VIRTIO_CMD_QUERY_QP,
	                          &in, &out);

	if (rc)
		goto out;

	attr->qp_state = rsp->attr.qp_state;
	attr->cur_qp_state = rsp->attr.cur_qp_state;
	attr->path_mtu = rsp->attr.path_mtu;
	attr->path_mig_state = rsp->attr.path_mig_state;
	attr->qkey = rsp->attr.qkey;
	attr->rq_psn = rsp->attr.rq_psn;
	attr->sq_psn = rsp->attr.sq_psn;
	attr->dest_qp_num = rsp->attr.dest_qp_num;
	attr->qp_access_flags = rsp->attr.qp_access_flags;
	attr->pkey_index = rsp->attr.pkey_index;
	attr->alt_pkey_index = rsp->attr.alt_pkey_index;
	attr->en_sqd_async_notify = rsp->attr.en_sqd_async_notify;
	attr->sq_draining = rsp->attr.sq_draining;
	attr->max_rd_atomic = rsp->attr.max_rd_atomic;
	attr->max_dest_rd_atomic = rsp->attr.max_dest_rd_atomic;
	attr->min_rnr_timer = rsp->attr.min_rnr_timer;
	attr->port_num = rsp->attr.port_num;
	attr->timeout = rsp->attr.timeout;
	attr->retry_cnt = rsp->attr.retry_cnt;
	attr->rnr_retry = rsp->attr.rnr_retry;
	attr->alt_port_num = rsp->attr.alt_port_num;
	attr->alt_timeout = rsp->attr.alt_timeout;
	attr->rate_limit = rsp->attr.rate_limit;
	virtio_rdma_to_ib_qp_cap(&attr->cap, &rsp->attr.cap);
	virtio_rdma_to_rdma_ah_attr(&attr->ah_attr, &rsp->attr.ah_attr);
	virtio_rdma_to_rdma_ah_attr(&attr->alt_ah_attr, &rsp->attr.alt_ah_attr);

out:
	init_attr->event_handler = vqp->ibqp.event_handler;
	init_attr->qp_context = vqp->ibqp.qp_context;
	init_attr->send_cq = vqp->ibqp.send_cq;
	init_attr->recv_cq = vqp->ibqp.recv_cq;
	init_attr->srq = vqp->ibqp.srq;
	init_attr->xrcd = NULL;
	init_attr->cap = attr->cap;
	init_attr->sq_sig_type = 0;
	init_attr->qp_type = vqp->ibqp.qp_type;
	init_attr->create_flags = 0;
	init_attr->port_num = vqp->port;

	kfree(cmd);
	kfree(rsp);
	return rc;
}

/* This verb is relevant only for InfiniBand */
int virtio_rdma_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
			   u16 *pkey)
{
	struct scatterlist in, out;
	struct cmd_query_pkey *cmd;
	struct rsp_query_pkey *rsp;
	int rc;
	
	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp) {
		kfree(cmd);
		return -ENOMEM;
	}

	cmd->port = port;
	cmd->index = index;

	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(ibdev), VIRTIO_CMD_QUERY_PKEY,
	                          &in, &out);

	*pkey = rsp->pkey;
	
	kfree(cmd);
	kfree(rsp);
	return rc;
}

int virtio_rdma_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct virtio_rdma_cq *vcq = to_vcq(ibcq);
	struct virtio_rdma_cqe *cqe;
	int i = 0;
	unsigned long flags;
	unsigned int tmp;
	struct scatterlist sg;
	struct virtqueue *vq = vcq->vq->vq;

	spin_lock_irqsave(&vcq->lock, flags);
	while (i < num_entries) {
		cqe = virtqueue_get_buf(vq, &tmp);
		if (!cqe)
			break;

		wc[i].wr_id = cqe->wr_id;
		wc[i].status = cqe->status;
		wc[i].opcode = cqe->opcode;
		wc[i].vendor_err = cqe->vendor_err;
		wc[i].byte_len = cqe->byte_len;
		// TODO: wc[i].qp
		wc[i].ex.imm_data = cqe->imm_data;
		wc[i].src_qp = cqe->src_qp;
		wc[i].slid = cqe->slid;
		wc[i].wc_flags = cqe->wc_flags;
		wc[i].pkey_index = cqe->pkey_index;
		wc[i].sl = cqe->sl;
		wc[i].dlid_path_bits = cqe->dlid_path_bits;

		sg_init_one(&sg, cqe, sizeof(*cqe));
		virtqueue_add_inbuf(vq, &sg, 1, cqe, GFP_KERNEL);
		i++;
	}
	spin_unlock_irqrestore(&vcq->lock, flags);
	return i;
}

int virtio_rdma_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
			  const struct ib_recv_wr **bad_wr)
{
	struct scatterlist *sgs[1], hdr;
	struct virtio_rdma_qp *vqp = to_vqp(ibqp);
	struct virtio_rdma_cmd_post_recv *cmd;
	int rc = 0, tmp;
	unsigned int sgl_len;
	void* ptr;

	if (vqp->ibqp.qp_type == IB_QPT_GSI || vqp->ibqp.qp_type == IB_QPT_SMI)
		return 0;

	spin_lock(&vqp->rq->lock);

	// TODO: check bad wr
	while (wr) {
		while ((ptr = virtqueue_get_buf(vqp->rq->vq, &tmp)) != NULL) {
			kfree(ptr);
		}

		sgl_len = sizeof(struct virtio_rdma_sge) * wr->num_sge;
		cmd = kzalloc(sizeof(*cmd) + sgl_len, GFP_ATOMIC);
		if (!cmd) {
			rc = -ENOMEM;
			goto out;
		}

		cmd->qpn = to_vqp(ibqp)->qp_handle;
		cmd->is_kernel = vqp->type == VIRTIO_RDMA_TYPE_KERNEL;
		cmd->num_sge = wr->num_sge;
		cmd->wr_id = wr->wr_id;
		memcpy((char*)cmd + sizeof(*cmd), wr->sg_list, sgl_len);

		sg_init_one(&hdr, cmd, sizeof(*cmd) + sgl_len);
		sgs[0] = &hdr;

		rc = virtqueue_add_sgs(vqp->rq->vq, sgs, 1, 0, cmd, GFP_ATOMIC);
		if (rc) {
			pr_err("post recv err %d", rc);
			goto out_err;
		}
		wr = wr->next;
	}

	virtqueue_kick(vqp->rq->vq);
	goto out;

out_err:
	*bad_wr = wr;
	kfree(cmd);
out:
	spin_unlock(&vqp->rq->lock);
	return rc;
}

int virtio_rdma_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			  const struct ib_send_wr **bad_wr)
{
	struct scatterlist *sgs[1], hdr;
	struct virtio_rdma_qp *vqp = to_vqp(ibqp);
	struct virtio_rdma_cmd_post_send *cmd;
	int rc = 0;
	unsigned tmp;
	unsigned int sgl_len;
	void* ptr;

	spin_lock(&vqp->sq->lock);

	while (wr) {
		if (vqp->type == VIRTIO_RDMA_TYPE_KERNEL &&
			wr->opcode != IB_WR_SEND && wr->opcode != IB_WR_SEND_WITH_IMM &&
			wr->opcode != IB_WR_REG_MR &&
			wr->opcode != IB_WR_LOCAL_INV && wr->opcode != IB_WR_SEND_WITH_INV) {
			pr_warn("Only support op send in kernel\n");
			rc = -EINVAL;
			goto out;
		}

		while ((ptr = virtqueue_get_buf(vqp->rq->vq, &tmp)) != NULL) {
			kfree(ptr);
		}

		sgl_len = sizeof(struct virtio_rdma_sge) * wr->num_sge;
		cmd = kzalloc(sizeof(*cmd) + sgl_len, GFP_ATOMIC);
		if (!cmd) {
			rc = -ENOMEM;
			goto out;
		}

		cmd->qpn = vqp->qp_handle;
		cmd->is_kernel = vqp->type == VIRTIO_RDMA_TYPE_KERNEL;
		cmd->num_sge = wr->num_sge;
		cmd->send_flags = wr->send_flags;
		cmd->opcode = wr->opcode;
		cmd->wr_id = wr->wr_id;
		cmd->ex.imm_data = wr->ex.imm_data;
		cmd->ex.invalidate_rkey = wr->ex.invalidate_rkey;

		switch (ibqp->qp_type) {
		case IB_QPT_GSI:
		case IB_QPT_UD:
			pr_err("Not support UD now\n");
			rc = -EINVAL;
			goto out_err;
			break;
		case IB_QPT_RC:
			switch (wr->opcode) {
			case IB_WR_RDMA_READ:
			case IB_WR_RDMA_WRITE:
			case IB_WR_RDMA_WRITE_WITH_IMM:
				cmd->wr.rdma.remote_addr =
					rdma_wr(wr)->remote_addr;
				cmd->wr.rdma.rkey = rdma_wr(wr)->rkey;
				break;
			case IB_WR_LOCAL_INV:
			case IB_WR_SEND_WITH_INV:
				cmd->ex.invalidate_rkey =
					wr->ex.invalidate_rkey;
				break;
			case IB_WR_ATOMIC_CMP_AND_SWP:
			case IB_WR_ATOMIC_FETCH_AND_ADD:
				cmd->wr.atomic.remote_addr =
					atomic_wr(wr)->remote_addr;
				cmd->wr.atomic.rkey = atomic_wr(wr)->rkey;
				cmd->wr.atomic.compare_add =
					atomic_wr(wr)->compare_add;
				if (wr->opcode == IB_WR_ATOMIC_CMP_AND_SWP)
					cmd->wr.atomic.swap =
						atomic_wr(wr)->swap;
				break;
			case IB_WR_REG_MR:
				cmd->wr.reg.mrn = to_vmr(reg_wr(wr)->mr)->mr_handle;
				cmd->wr.reg.key = reg_wr(wr)->key;
				cmd->wr.reg.access = reg_wr(wr)->access;
				break;
			default:
				break;
			}
			break;
		default:
			pr_err("Bad qp type\n");
			rc = -EINVAL;
			goto out_err;
		}
		memcpy((char*)cmd + sizeof(*cmd), wr->sg_list, sgl_len);

		sg_init_one(&hdr, cmd, sizeof(*cmd) + sgl_len);
		sgs[0] = &hdr;

		rc = virtqueue_add_sgs(vqp->sq->vq, sgs, 1, 0, cmd, GFP_ATOMIC);
		if (rc) {
			pr_err("post send err %d", rc);
			goto out_err;
		}

		wr = wr->next;
	}

	virtqueue_kick(vqp->sq->vq);
	goto out;

out_err:
	*bad_wr = wr;
	kfree(cmd);
out:
	spin_unlock(&vqp->sq->lock);
	return rc;
}

int virtio_rdma_req_notify_cq(struct ib_cq *ibcq,
			      enum ib_cq_notify_flags flags)
{
	struct virtio_rdma_cq *vcq = to_vcq(ibcq);
	struct cmd_req_notify *cmd;
	struct rsp_req_notify *rsp;
	struct scatterlist in, out;
	int rc;

	if (flags & IB_CQ_SOLICITED_MASK) {
		cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
		if (!cmd)
			return -ENOMEM;

		rsp = kzalloc(sizeof(*rsp), GFP_ATOMIC);
		if (!rsp) {
			kfree(cmd);
			return -ENOMEM;
		}

		cmd->cqn = vcq->cq_handle;
		cmd->flags = (flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED ?
			VIRTIO_RDMA_NOTIFY_SOLICITED : VIRTIO_RDMA_NOTIFY_NEXT_COMPLETION;

		sg_init_one(&in, cmd, sizeof(*cmd));
		sg_init_one(&out, rsp, sizeof(*rsp));

		rc = virtio_rdma_exec_cmd(to_vdev(ibcq->device),
								  VIRTIO_CMD_REQ_NOTIFY_CQ, &in, &out);
		
		kfree(cmd);
		kfree(rsp);
		if (!rc)
			return -EIO;
	}

	if (flags & IB_CQ_REPORT_MISSED_EVENTS)
		return vcq->vq->vq->num_free;

	return 0;
}

static ssize_t hca_type_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "VIRTIO-RDMA-%s\n", VIRTIO_RDMA_DRIVER_VER);
}
static DEVICE_ATTR_RO(hca_type);

static ssize_t hw_rev_show(struct device *device,
			   struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", VIRTIO_RDMA_HW_REV);
}
static DEVICE_ATTR_RO(hw_rev);

static ssize_t board_id_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", VIRTIO_RDMA_BOARD_ID);
}
static DEVICE_ATTR_RO(board_id);

static struct attribute *virtio_rdma_class_attributes[] = {
	&dev_attr_hw_rev.attr,
	&dev_attr_hca_type.attr,
	&dev_attr_board_id.attr,
	NULL,
};

static const struct attribute_group virtio_rdma_attr_group = {
	.attrs = virtio_rdma_class_attributes,
};

static const struct ib_device_ops virtio_rdma_dev_ops = {
	.owner = THIS_MODULE,
	.uverbs_abi_ver = VIRTIO_RDMA_ABI_VERSION,
	.driver_id = RDMA_DRIVER_VIRTIO,

	.get_port_immutable = virtio_rdma_port_immutable,
	.query_device = virtio_rdma_query_device,
	.query_port = virtio_rdma_query_port,
	.get_netdev = virtio_rdma_get_netdev,
	.create_cq = virtio_rdma_create_cq,
	.destroy_cq = virtio_rdma_destroy_cq,
	.alloc_pd = virtio_rdma_alloc_pd,
	.dealloc_pd = virtio_rdma_dealloc_pd,
	.get_dma_mr = virtio_rdma_get_dma_mr,
	.create_qp = virtio_rdma_create_qp,
	.query_gid = virtio_rdma_query_gid,
	.add_gid = virtio_rdma_add_gid,
	.alloc_mr = virtio_rdma_alloc_mr,
	.alloc_ucontext = virtio_rdma_alloc_ucontext,
	.create_ah = virtio_rdma_create_ah,
	.dealloc_ucontext = virtio_rdma_dealloc_ucontext,
	.del_gid = virtio_rdma_del_gid,
	.dereg_mr = virtio_rdma_dereg_mr,
	.destroy_ah = virtio_rdma_destroy_ah,
	.destroy_qp = virtio_rdma_destroy_qp,
	.get_dev_fw_str = virtio_rdma_get_fw_ver_str,
	.get_link_layer = virtio_rdma_port_link_layer,
	.map_mr_sg = virtio_rdma_map_mr_sg,
	.mmap = virtio_rdma_mmap,
	.mmap_free = virtio_rdma_mmap_free,
	.modify_port = virtio_rdma_modify_port,
	.modify_qp = virtio_rdma_modify_qp,
	.poll_cq = virtio_rdma_poll_cq,
	.post_recv = virtio_rdma_post_recv,
	.post_send = virtio_rdma_post_send,
	.query_device = virtio_rdma_query_device,
	.query_pkey = virtio_rdma_query_pkey,
	.query_qp = virtio_rdma_query_qp,
	.reg_user_mr = virtio_rdma_reg_user_mr,
	.req_notify_cq = virtio_rdma_req_notify_cq,

	.device_group = &virtio_rdma_attr_group,

	INIT_RDMA_OBJ_SIZE(ib_ah, virtio_rdma_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, virtio_rdma_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, virtio_rdma_pd, ibpd),
	// INIT_RDMA_OBJ_SIZE(ib_srq, virtio_rdma_srq, base_srq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, virtio_rdma_ucontext, ibucontext),
};

int virtio_rdma_register_ib_device(struct virtio_rdma_dev *ri)
{
	int rc;
	struct ib_device *dev =  &ri->ib_dev;

	strlcpy(dev->node_desc, "VirtIO RDMA", sizeof(dev->node_desc));

	dev->num_comp_vectors = 1;
	dev->dev.parent = ri->vdev->dev.parent;
	dev->node_type = RDMA_NODE_IB_CA;
	dev->uverbs_cmd_mask |=
		(1ull << IB_USER_VERBS_CMD_POST_SEND)|
		(1ull << IB_USER_VERBS_CMD_POST_RECV);

    ib_set_device_ops(dev, &virtio_rdma_dev_ops);
	ib_device_set_netdev(dev, ri->netdev, 1);

	rc = ib_register_device(dev, "virtio_rdma%d", NULL);

	memcpy(&dev->node_guid, dev->name, 6);
	return rc;
}

void virtio_rdma_unregister_ib_device(struct virtio_rdma_dev *ri)
{
	ib_unregister_device(&ri->ib_dev);
}
