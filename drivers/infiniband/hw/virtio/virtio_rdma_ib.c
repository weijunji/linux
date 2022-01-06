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
	[VIRTIO_CMD_CREATE_UC] = "VIRTIO_CMD_CREATE_UC",
	[VIRTIO_CMD_DEALLOC_UC] = "VIRTIO_CMD_DEALLOC_UC",
	[VIRTIO_CMD_QUERY_PKEY] = "VIRTIO_CMD_QUERY_PKEY",
	[VIRTIO_CMD_ADD_GID] = "VIRTIO_CMD_ADD_GID",
	[VIRTIO_CMD_DEL_GID] = "VIRTIO_CMD_DEL_GID",
	[VIRTIO_CMD_REQ_NOTIFY_CQ] = "VIRTIO_CMD_REQ_NOTIFY_CQ",
};

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

static int virtio_rdma_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata);

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

	if (udata) {
		struct virtio_rdma_alloc_pd_uresp uresp = {};
		if (ib_copy_to_udata(udata, &uresp, sizeof(uresp))) {
			pr_warn("failed to copy back protection domain\n");
			virtio_rdma_dealloc_pd(&pd->ibpd, udata);
			return -EFAULT;
		}
	}

	pr_info("%s: pd_handle=%d\n", __func__, pd->pd_handle);

out:
	kfree(rsp);
	kfree(cmd);
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
	int i, rc = -ENOMEM;
	int entries = attr->cqe;
	size_t total_size;
	struct virtio_rdma_user_mmap_entry* entry = NULL;

	if (!atomic_add_unless(&vdev->num_cq, 1, ibcq->device->attrs.max_cq))
		return -ENOMEM;

	total_size = vcq->queue_size = PAGE_ALIGN(entries * sizeof(*vcq->queue));
	vcq->queue = dma_alloc_coherent(vdev->vdev->dev.parent, vcq->queue_size,
					&vcq->dma_addr, GFP_KERNEL);
	if (!vcq->queue)
		return -ENOMEM;

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		goto err_cmd;

	rsp = kmalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp)
		goto err_rsp;
	
	if (udata) {
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (!entry)
			goto err;
	}

	cmd->cqe = attr->cqe;
	sg_init_one(&in, cmd, sizeof(*cmd));
	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(vdev, VIRTIO_CMD_CREATE_CQ, &in,
				  &out);
	if (rc)
		goto err;

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
		entry->ubuf_size = vcq->queue_size;

		uresp.used_off = virtqueue_get_used_addr(vcq->vq->vq) -
					virtqueue_get_desc_addr(vcq->vq->vq);

		uresp.vq_size = PAGE_ALIGN(vring_size(virtqueue_get_vring_size(vcq->vq->vq), SMP_CACHE_BYTES));
		total_size += uresp.vq_size;

		rc = rdma_user_mmap_entry_insert(&uctx->ibucontext, &entry->rdma_entry,
			total_size);
		if (rc)
			goto err;

		uresp.offset = rdma_user_mmap_get_offset(&entry->rdma_entry);
		uresp.cq_phys_addr = virt_to_phys(vcq->queue);
		uresp.num_cqe = entries;
		uresp.num_cvqe = virtqueue_get_vring_size(vcq->vq->vq);
		uresp.cq_size = total_size;

		if (udata->outlen < sizeof(uresp)) {
			rc = -EINVAL;
			goto err;
		}
		rc = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rc)
			goto err;

		vcq->entry = &entry->rdma_entry;
	} else {
		for(i = 0; i < entries; i++) {
			sg_init_one(&sg, vcq->queue + i, sizeof(*vcq->queue));
			virtqueue_add_inbuf(vcq->vq->vq, &sg, 1, vcq->queue + i, GFP_KERNEL);
		}
	}

	spin_lock_init(&vcq->lock);

	kfree(rsp);
	kfree(cmd);
	return 0;

err:
	if (entry)
		kfree(entry);
	kfree(rsp);
err_rsp:
	kfree(cmd);
err_cmd:
	dma_free_coherent(vdev->vdev->dev.parent, vcq->queue_size,
			  vcq->queue, vcq->dma_addr);
	return rc;
}

static int virtio_rdma_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
{
	struct virtio_rdma_cq *vcq = to_vcq(cq);
	struct virtio_rdma_dev *vdev = to_vdev(cq->device);
	struct scatterlist in;
	struct cmd_destroy_cq *cmd;

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	cmd->cqn = vcq->cq_handle;
	sg_init_one(&in, cmd, sizeof(*cmd));

	virtqueue_disable_cb(vcq->vq->vq);

	virtio_rdma_exec_cmd(to_vdev(cq->device), VIRTIO_CMD_DESTROY_CQ,
				  &in, NULL);

	/* pop all from virtqueue, after host call virtqueue_drop_all,
	 * prepare for next use.
	 */
	if (!udata)
		while(virtqueue_detach_unused_buf(vcq->vq->vq));

	atomic_dec(&to_vdev(cq->device)->num_cq);
	virtqueue_enable_cb(vcq->vq->vq);

	if (vcq->entry)
		rdma_user_mmap_entry_remove(vcq->entry);

	to_vdev(cq->device)->cqs[vcq->cq_handle] = NULL;

	dma_free_coherent(vdev->vdev->dev.parent, vcq->queue_size,
					vcq->queue, vcq->dma_addr);
	kfree(cmd);
	return 0;
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
		if (rc)
			return -EIO;
	}

	// FIXME: not support in userspace
	if (flags & IB_CQ_REPORT_MISSED_EVENTS)
		return -EOPNOTSUPP;

	return 0;
}

static void* virtio_rdma_init_mmap_entry(struct virtio_rdma_dev *vdev,
		struct virtqueue *vq,
		struct virtio_rdma_user_mmap_entry** entry_, int buf_size,
		struct virtio_rdma_ucontext* vctx, __u64* size, __u64* used_off,
		__u32* vq_size, dma_addr_t *dma_addr)
{
	void* buf = NULL;
	int rc;
	size_t total_size;
	struct virtio_rdma_user_mmap_entry* entry;

	total_size = PAGE_ALIGN(buf_size);
	buf = dma_alloc_coherent(vdev->vdev->dev.parent, total_size,
							dma_addr, GFP_KERNEL);
	if (!buf)
		return NULL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		dma_free_coherent(vdev->vdev->dev.parent, total_size,
						buf, *dma_addr);
		return NULL;
	}

	entry->type = VIRTIO_RDMA_MMAP_QP;
	entry->queue = vq;
	entry->ubuf = buf;
	entry->ubuf_size = PAGE_ALIGN(buf_size);

	*used_off = virtqueue_get_used_addr(vq) - virtqueue_get_desc_addr(vq);
	*vq_size = PAGE_ALIGN(vring_size(virtqueue_get_vring_size(vq), SMP_CACHE_BYTES));
	total_size += *vq_size + PAGE_SIZE;

	rc = rdma_user_mmap_entry_insert(&vctx->ibucontext, &entry->rdma_entry,
			total_size);
	if (rc) {
		dma_free_coherent(vdev->vdev->dev.parent, total_size,
						buf, *dma_addr);
		return NULL;
	}

	*size = total_size;
	*entry_ = entry;
	return buf;
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
	props->active_mtu = port_attr.active_mtu;
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

static void virtio_rdma_get_fw_ver_str(struct ib_device *device, char *str)
{
	snprintf(str, IB_FW_VERSION_NAME_MAX, "%d.%d.%d\n", 1, 0, 0);
}

static enum rdma_link_layer virtio_rdma_port_link_layer(struct ib_device *ibdev,
						 u32 port)
{
	return IB_LINK_LAYER_ETHERNET;
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
	dev->uverbs_cmd_mask = BIT_ULL(IB_USER_VERBS_CMD_GET_CONTEXT)
	| BIT_ULL(IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)
	| BIT_ULL(IB_USER_VERBS_CMD_QUERY_DEVICE)
	| BIT_ULL(IB_USER_VERBS_CMD_QUERY_PORT)
	| BIT_ULL(IB_USER_VERBS_CMD_ALLOC_PD)
	| BIT_ULL(IB_USER_VERBS_CMD_DEALLOC_PD)
	| BIT_ULL(IB_USER_VERBS_CMD_CREATE_QP)
	| BIT_ULL(IB_USER_VERBS_CMD_MODIFY_QP)
	| BIT_ULL(IB_USER_VERBS_CMD_QUERY_QP)
	| BIT_ULL(IB_USER_VERBS_CMD_DESTROY_QP)
	| BIT_ULL(IB_USER_VERBS_CMD_POST_SEND)
	| BIT_ULL(IB_USER_VERBS_CMD_POST_RECV)
	| BIT_ULL(IB_USER_VERBS_CMD_CREATE_CQ)
	| BIT_ULL(IB_USER_VERBS_CMD_DESTROY_CQ)
	| BIT_ULL(IB_USER_VERBS_CMD_POLL_CQ)
	| BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ)
	| BIT_ULL(IB_USER_VERBS_CMD_REG_MR)
	| BIT_ULL(IB_USER_VERBS_CMD_DEREG_MR)
	| BIT_ULL(IB_USER_VERBS_CMD_CREATE_AH)
	| BIT_ULL(IB_USER_VERBS_CMD_MODIFY_AH)
	| BIT_ULL(IB_USER_VERBS_CMD_QUERY_AH)
	| BIT_ULL(IB_USER_VERBS_CMD_DESTROY_AH);

    ib_set_device_ops(dev, &virtio_rdma_dev_ops);
	ib_device_set_netdev(dev, ri->netdev, 1);

	rc = ib_register_device(dev, "virtio_rdma%d", ri->vdev->dev.parent);

	memcpy(&dev->node_guid, dev->name, 6);
	return rc;
}

void virtio_rdma_unregister_ib_device(struct virtio_rdma_dev *ri)
{
	ib_unregister_device(&ri->ib_dev);
}
