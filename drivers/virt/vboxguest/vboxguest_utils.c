/*
 * vboxguest vmm-req and hgcm-call code, VBoxGuestR0LibHGCMInternal.cpp,
 * VBoxGuestR0LibGenericRequest.cpp and RTErrConvertToErrno.cpp in vbox svn.
 *
 * Copyright (C) 2006-2016 Oracle Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL) only, in which case the provisions of the CDDL are applicable
 * instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/vbox_err.h>
#include <linux/vbox_utils.h>
#include "vboxguest_core.h"

/* Get the pointer to the first HGCM parameter. */
#define VBGL_HGCM_CALL_PARMS(a) \
	((struct hgcm_function_parameter *)( \
		(u8 *)(a) + sizeof(VBGLIOCHGCMCALL)))
/* Get the pointer to the first HGCM parameter in a 32-bit request. */
#define VBGL_HGCM_CALL_PARMS32(a) \
	((struct hgcm_function_parameter32 *)( \
		(u8 *)(a) + sizeof(VBGLIOCHGCMCALL)))
/* Get the pointer to the first parameter of a HGCM call request. */
#define VMMDEV_HGCM_CALL_PARMS(a) \
	((struct hgcm_function_parameter *)( \
		(u8 *)(a) + sizeof(struct vmmdev_hgcm_call)))

/* The max parameter buffer size for a user request. */
#define VBGLR0_MAX_HGCM_USER_PARM	(24 * SZ_1M)
/* The max parameter buffer size for a kernel request. */
#define VBGLR0_MAX_HGCM_KERNEL_PARM	(16 * SZ_1M)

#define VBG_DEBUG_PORT			0x504

/*
 * Macro for validating that the specified flags are valid.
 * Note BOTH is not valid.
 */
#define VBOX_HGCM_F_PARM_ARE_VALID(fFlags) \
	((fFlags) > VBOX_HGCM_F_PARM_DIRECTION_NONE && \
	 (fFlags) < VBOX_HGCM_F_PARM_DIRECTION_BOTH)

/* This protects vbg_log_buf and serializes VBG_DEBUG_PORT accesses */
static DEFINE_SPINLOCK(vbg_log_lock);
static char vbg_log_buf[128];

#define VBG_LOG(name, pr_func) \
void name(const char *fmt, ...)						\
{									\
	unsigned long flags;						\
	va_list args;							\
	int i, count;							\
									\
	va_start(args, fmt);						\
	spin_lock_irqsave(&vbg_log_lock, flags);			\
									\
	count = vscnprintf(vbg_log_buf, sizeof(vbg_log_buf), fmt, args);\
	for (i = 0; i < count; i++)					\
		outb(vbg_log_buf[i], VBG_DEBUG_PORT);			\
									\
	pr_func("%s", vbg_log_buf);					\
									\
	spin_unlock_irqrestore(&vbg_log_lock, flags);			\
	va_end(args);							\
}									\
EXPORT_SYMBOL(name)

VBG_LOG(vbg_info, pr_info);
VBG_LOG(vbg_warn, pr_warn);
VBG_LOG(vbg_err, pr_err);
#if defined(DEBUG) && !defined(CONFIG_DYNAMIC_DEBUG)
VBG_LOG(vbg_debug, pr_debug);
#endif

void *vbg_req_alloc(size_t len, enum vmmdev_request_type req_type)
{
	struct vmmdev_request_header *req;

	req = kmalloc(len, GFP_KERNEL | __GFP_DMA32);
	if (!req)
		return NULL;

	memset(req, 0xaa, len);

	req->size = len;
	req->version = VMMDEV_REQUEST_HEADER_VERSION;
	req->requestType = req_type;
	req->rc = VERR_GENERAL_FAILURE;
	req->reserved1 = 0;
	req->reserved2 = 0;

	return req;
}

/* Note this function returns a VBox status code, not a negative errno!! */
int vbg_req_perform(struct vbg_dev *gdev, void *req)
{
	unsigned long phys_req = virt_to_phys(req);

	outl(phys_req, gdev->io_port + VMMDEV_PORT_OFF_REQUEST);
	/*
	 * The host changes the request as a result of the outl, make sure
	 * the outl and any reads of the req happen in the correct order.
	 */
	mb();

	return ((struct vmmdev_request_header *)req)->rc;
}

static bool hgcm_req_done(struct vbg_dev *gdev,
			  struct vmmdev_hgcmreq_header *header)
{
	unsigned long flags;
	bool done;

	spin_lock_irqsave(&gdev->event_spinlock, flags);
	done = header->fu32Flags & VBOX_HGCM_REQ_DONE;
	spin_unlock_irqrestore(&gdev->event_spinlock, flags);

	return done;
}

int vbg_hgcm_connect(struct vbg_dev *gdev, struct hgcm_service_location *loc,
		     u32 *client_id, int *vbox_status)
{
	struct vmmdev_hgcm_connect *hgcm_connect = NULL;
	int rc;

	hgcm_connect = vbg_req_alloc(sizeof(*hgcm_connect),
				     VMMDevReq_HGCMConnect);
	if (!hgcm_connect)
		return -ENOMEM;

	hgcm_connect->header.fu32Flags = 0;
	memcpy(&hgcm_connect->loc, loc, sizeof(*loc));
	hgcm_connect->u32ClientID = 0;

	rc = vbg_req_perform(gdev, hgcm_connect);

	if (rc == VINF_HGCM_ASYNC_EXECUTE)
		wait_event(gdev->hgcm_wq,
			   hgcm_req_done(gdev, &hgcm_connect->header));

	if (rc >= 0) {
		*client_id = hgcm_connect->u32ClientID;
		rc = hgcm_connect->header.result;
	}

	kfree(hgcm_connect);

	*vbox_status = rc;
	return 0;
}
EXPORT_SYMBOL(vbg_hgcm_connect);

int vbg_hgcm_disconnect(struct vbg_dev *gdev, u32 client_id, int *vbox_status)
{
	struct vmmdev_hgcm_disconnect *hgcm_disconnect = NULL;
	int rc;

	hgcm_disconnect = vbg_req_alloc(sizeof(*hgcm_disconnect),
					VMMDevReq_HGCMDisconnect);
	if (!hgcm_disconnect)
		return -ENOMEM;

	hgcm_disconnect->header.fu32Flags = 0;
	hgcm_disconnect->u32ClientID = client_id;

	rc = vbg_req_perform(gdev, hgcm_disconnect);

	if (rc == VINF_HGCM_ASYNC_EXECUTE)
		wait_event(gdev->hgcm_wq,
			   hgcm_req_done(gdev, &hgcm_disconnect->header));

	if (rc >= 0)
		rc = hgcm_disconnect->header.result;

	kfree(hgcm_disconnect);

	*vbox_status = rc;
	return 0;
}
EXPORT_SYMBOL(vbg_hgcm_disconnect);

static u32 hgcm_call_buf_size_in_pages(void *buf, u32 len)
{
	u32 size = PAGE_ALIGN(len + ((unsigned long)buf & ~PAGE_MASK));

	return size >> PAGE_SHIFT;
}

static void hgcm_call_add_pagelist_size(void *buf, u32 len, size_t *extra)
{
	u32 pages;

	pages = hgcm_call_buf_size_in_pages(buf, len);
	*extra += offsetof(struct hgcm_pagelist, aPages[pages]);
}

/* Kernel mode use only, use WARN_ON for sanity checks. */
static int hgcm_call_check_pagelist(
	const struct hgcm_function_parameter *src_parm,
	const VBGLIOCHGCMCALL *info, size_t *extra)
{
	struct hgcm_pagelist *pg_lst;
	u32 u, offset, size, param_size;
	offset = src_parm->u.PageList.offset;
	size = src_parm->u.PageList.size;
	if (!size)
		return 0;

	if (WARN_ON(size > VBGLR0_MAX_HGCM_KERNEL_PARM))
		return -E2BIG;

	param_size = info->cParms * sizeof(struct hgcm_function_parameter);
	if (WARN_ON(offset < param_size ||
		    offset > info->Hdr.cbIn - sizeof(struct hgcm_pagelist)))
		return -EINVAL;

	pg_lst = (struct hgcm_pagelist *)((u8 *)info + offset);

	u = offset + offsetof(struct hgcm_pagelist, aPages[pg_lst->cPages]);
	if (WARN_ON(u > info->Hdr.cbIn))
		return -EINVAL;

	if (WARN_ON(pg_lst->offFirstPage >= PAGE_SIZE))
		return -EINVAL;

	u = PAGE_ALIGN(pg_lst->offFirstPage + size) >> PAGE_SHIFT;
	if (WARN_ON(u != pg_lst->cPages))
		return -EINVAL;

	if (WARN_ON(!VBOX_HGCM_F_PARM_ARE_VALID(pg_lst->flags)))
		return -EINVAL;

	for (u = 0; u < pg_lst->cPages; u++) {
		if (WARN_ON(pg_lst->aPages[u] &
			    (0xfff0000000000000ULL | ~PAGE_MASK)))
			return -EINVAL;
	}

	*extra += offsetof(struct hgcm_pagelist, aPages[pg_lst->cPages]);

	return 0;
}

static int hgcm_call_preprocess_linaddr(
	const struct hgcm_function_parameter *src_parm, bool is_user,
	void **bounce_buf_ret, size_t *extra)
{
	void *buf, *bounce_buf;
	bool copy_in;
	u32 len;
	int ret;

	buf = (void *)src_parm->u.Pointer.u.linearAddr;
	len = src_parm->u.Pointer.size;
	copy_in = src_parm->type != VMMDevHGCMParmType_LinAddr_Out;

	if (!is_user) {
		if (WARN_ON(len > VBGLR0_MAX_HGCM_KERNEL_PARM))
			return -E2BIG;

		hgcm_call_add_pagelist_size(buf, len, extra);
		return 0;
	}

	if (len > VBGLR0_MAX_HGCM_USER_PARM)
		return -E2BIG;

	bounce_buf = kvmalloc(len, GFP_KERNEL);
	if (!bounce_buf)
		return -ENOMEM;

	if (copy_in) {
		ret = copy_from_user(bounce_buf, (void __user *)buf, len);
		if (ret)
			return -EFAULT;
	} else {
		memset(bounce_buf, 0, len);
	}

	*bounce_buf_ret = bounce_buf;
	hgcm_call_add_pagelist_size(bounce_buf, len, extra);
	return 0;
}

/**
 * Preprocesses the HGCM call, validate parameters, alloc bounce buffers and
 * figure out how much extra storage we need for page lists.
 *
 * @returns 0 or negative errno value.
 *
 * @param   info             The call info.
 * @param   is_user          Is it a user request or kernel request.
 * @param   bounce_bufs_ret  Where to return the allocated bouncebuffer array
 * @param   extra            Where to return the extra request space needed for
 *                           physical page lists.
 */
static int hgcm_call_preprocess(const VBGLIOCHGCMCALL *info, bool is_user,
				void ***bounce_bufs_ret, size_t *extra)
{
	const struct hgcm_function_parameter *src_parm =
		VBGL_HGCM_CALL_PARMS(info);
	u32 i, parms = info->cParms;
	void **bounce_bufs = NULL;
	int ret;

	*bounce_bufs_ret = NULL;
	*extra = 0;

	for (i = 0; i < parms; i++, src_parm++) {
		switch (src_parm->type) {
		case VMMDevHGCMParmType_32bit:
		case VMMDevHGCMParmType_64bit:
			break;

		case VMMDevHGCMParmType_PageList:
			if (is_user)
				return -EINVAL;

			ret = hgcm_call_check_pagelist(src_parm, info, extra);
			if (ret)
				return ret;

			break;

		case VMMDevHGCMParmType_LinAddr_In:
		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
			if (is_user && !bounce_bufs) {
				bounce_bufs = kcalloc(parms, sizeof(void *),
						      GFP_KERNEL);
				if (!bounce_bufs)
					return -ENOMEM;

				*bounce_bufs_ret = bounce_bufs;
			}

			ret = hgcm_call_preprocess_linaddr(src_parm, is_user,
							   &bounce_bufs[i],
							   extra);
			if (ret)
				return ret;

			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * Translates linear address types to page list direction flags.
 *
 * @returns page list flags.
 * @param   type	The type.
 */
static u32 hgcm_call_linear_addr_type_to_pagelist_flags(
	enum hgcm_function_parameter_type type)
{
	switch (type) {
	case VMMDevHGCMParmType_LinAddr_In:
		return VBOX_HGCM_F_PARM_DIRECTION_TO_HOST;

	case VMMDevHGCMParmType_LinAddr_Out:
		return VBOX_HGCM_F_PARM_DIRECTION_FROM_HOST;

	default:
		WARN_ON(1);
	case VMMDevHGCMParmType_LinAddr:
		return VBOX_HGCM_F_PARM_DIRECTION_BOTH;
	}
}

static void hgcm_call_init_pagelist(
	struct vmmdev_hgcm_call *call, const VBGLIOCHGCMCALL *info,
	struct hgcm_function_parameter *dst_parm,
	const struct hgcm_function_parameter *src_parm,
	u32 *off_extra)
{
	const struct hgcm_pagelist *src_pg_list;
	struct hgcm_pagelist *dst_pg_list;
	u32 i, pages;

	dst_parm->type = VMMDevHGCMParmType_PageList;
	dst_parm->u.PageList.size = src_parm->u.PageList.size;

	if (src_parm->u.PageList.size == 0) {
		dst_parm->u.PageList.offset = 0;
		return;
	}

	src_pg_list = (void *)info + src_parm->u.PageList.offset;
	dst_pg_list = (void *)call + *off_extra;
	pages = src_pg_list->cPages;

	dst_parm->u.PageList.offset = *off_extra;
	dst_pg_list->flags = src_pg_list->flags;
	dst_pg_list->offFirstPage = src_pg_list->offFirstPage;
	dst_pg_list->cPages = pages;

	for (i = 0; i < pages; i++)
		dst_pg_list->aPages[i] = src_pg_list->aPages[i];

	*off_extra += offsetof(struct hgcm_pagelist, aPages[pages]);
}

static void hgcm_call_init_linaddr(struct vmmdev_hgcm_call *call,
				   struct hgcm_function_parameter *dst_parm,
				   void *buf, u32 len,
				   enum hgcm_function_parameter_type type,
				   u32 *off_extra)
{
	struct hgcm_pagelist *dst_pg_lst;
	struct page *page;
	bool is_vmalloc;
	u32 i, pages;

	dst_parm->type = type;

	if (len == 0) {
		dst_parm->u.Pointer.size = 0;
		dst_parm->u.Pointer.u.linearAddr = 0;
		return;
	}

	dst_pg_lst = (void *)call + *off_extra;
	pages = hgcm_call_buf_size_in_pages(buf, len);
	is_vmalloc = is_vmalloc_addr(buf);

	dst_parm->type = VMMDevHGCMParmType_PageList;
	dst_parm->u.PageList.size = len;
	dst_parm->u.PageList.offset = *off_extra;
	dst_pg_lst->flags = hgcm_call_linear_addr_type_to_pagelist_flags(type);
	dst_pg_lst->offFirstPage = (unsigned long)buf & ~PAGE_MASK;
	dst_pg_lst->cPages = pages;

	for (i = 0; i < pages; i++) {
		if (is_vmalloc)
			page = vmalloc_to_page(buf);
		else
			page = virt_to_page(buf);

		dst_pg_lst->aPages[i] = page_to_phys(page);
		buf += PAGE_SIZE;
	}

	*off_extra += offsetof(struct hgcm_pagelist, aPages[pages]);
}

/**
 * Initializes the call request that we're sending to the host.
 *
 * @param   call            The call to initialize.
 * @param   info            The call info.
 * @param   bounce_bufs     The bouncebuffer array.
 */
static void hgcm_call_init_call(struct vmmdev_hgcm_call *call,
				const VBGLIOCHGCMCALL *info,
				void **bounce_bufs)
{
	const struct hgcm_function_parameter *src_parm =
		VBGL_HGCM_CALL_PARMS(info);
	struct hgcm_function_parameter *dst_parm = VMMDEV_HGCM_CALL_PARMS(call);
	u32 i, parms = info->cParms;
	u32 off_extra = (uintptr_t)(dst_parm + parms) - (uintptr_t)call;
	void *buf;

	call->header.fu32Flags = 0;
	call->header.result = VINF_SUCCESS;
	call->u32ClientID = info->u32ClientID;
	call->u32Function = info->u32Function;
	call->cParms = parms;

	for (i = 0; i < parms; i++, src_parm++, dst_parm++) {
		switch (src_parm->type) {
		case VMMDevHGCMParmType_32bit:
		case VMMDevHGCMParmType_64bit:
			*dst_parm = *src_parm;
			break;

		case VMMDevHGCMParmType_PageList:
			hgcm_call_init_pagelist(call, info, dst_parm, src_parm,
						&off_extra);
			break;

		case VMMDevHGCMParmType_LinAddr_In:
		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
			if (bounce_bufs && bounce_bufs[i])
				buf = bounce_bufs[i];
			else
				buf = (void *)src_parm->u.Pointer.u.linearAddr;

			hgcm_call_init_linaddr(call, dst_parm, buf,
					       src_parm->u.Pointer.size,
					       src_parm->type, &off_extra);
			break;

		default:
			WARN_ON(1);
			dst_parm->type = VMMDevHGCMParmType_Invalid;
		}
	}
}

/**
 * Tries to cancel a pending HGCM call.
 *
 * @returns VBox status code
 */
static int hgcm_cancel_call(struct vbg_dev *gdev, struct vmmdev_hgcm_call *call)
{
	int rc;

	/*
	 * We use a pre-allocated request for cancellations, which is
	 * protected by cancel_req_mutex. This means that all cancellations
	 * get serialized, this should be fine since they should be rare.
	 */
	mutex_lock(&gdev->cancel_req_mutex);
	gdev->cancel_req->physReqToCancel = virt_to_phys(call);
	rc = vbg_req_perform(gdev, gdev->cancel_req);
	mutex_unlock(&gdev->cancel_req_mutex);

	/** @todo ADDVER: Remove this on next minor version change. */
	if (rc == VERR_NOT_IMPLEMENTED) {
		call->header.fu32Flags |= VBOX_HGCM_REQ_CANCELLED;
		call->header.header.requestType = VMMDevReq_HGCMCancel;

		rc = vbg_req_perform(gdev, call);
		if (rc == VERR_INVALID_PARAMETER)
			rc = VERR_NOT_FOUND;
	}

	if (rc >= 0)
		call->header.fu32Flags |= VBOX_HGCM_REQ_CANCELLED;

	return rc;
}

/**
 * Performs the call and completion wait.
 *
 * @returns 0 or negative errno value.
 *
 * @param   gdev	The VBoxGuest device extension.
 * @param   call        The call to execute.
 * @param   info        The call info.
 * @param   timeout_ms	Timeout in ms.
 * @param   is_user	Is this an in kernel call or from userspace ?
 * @param   leak_it	Where to return the leak it / free it,
 *			indicator. Cancellation fun.
 */
static int vbg_hgcm_do_call(struct vbg_dev *gdev, struct vmmdev_hgcm_call *call,
			    VBGLIOCHGCMCALL *info, bool is_user, bool *leak_it)
{
	int rc, cancel_rc, ret;
	long timeout;

	*leak_it = false;

	rc = vbg_req_perform(gdev, call);

	/*
	 * If the call failed, then pretend success. Upper layers will
	 * interpret the result code in the packet.
	 */
	if (rc < 0) {
		call->header.result = rc;
		return 0;
	}

	if (rc != VINF_HGCM_ASYNC_EXECUTE)
		return 0;

	/* Host decided to process the request asynchronously, wait for it */
	if (info->cMsTimeout == U32_MAX)
		timeout = MAX_SCHEDULE_TIMEOUT;
	else
		timeout = msecs_to_jiffies(info->cMsTimeout);

	if (is_user) {
		timeout = wait_event_interruptible_timeout(gdev->hgcm_wq,
							   hgcm_req_done
							   (gdev,
							    &call->header),
							   timeout);
	} else {
		timeout = wait_event_timeout(gdev->hgcm_wq,
					     hgcm_req_done(gdev,
							   &call->header),
					     timeout);
	}

	/* timeout > 0 means hgcm_req_done has returned true, so success */
	if (timeout > 0)
		return 0;

	if (timeout == 0)
		ret = -ETIMEDOUT;
	else
		ret = -EINTR;

	/* Cancel the request */
	cancel_rc = hgcm_cancel_call(gdev, call);
	if (cancel_rc >= 0)
		return ret;

	/*
	 * Failed to cancel, this should mean that the cancel has lost the
	 * race with normal completion, wait while the host completes it.
	 */
	if (cancel_rc == VERR_NOT_FOUND || cancel_rc == VERR_SEM_DESTROYED)
		timeout = msecs_to_jiffies(500);
	else
		timeout = msecs_to_jiffies(2000);

	timeout = wait_event_timeout(gdev->hgcm_wq,
				     hgcm_req_done(gdev, &call->header),
				     timeout);

	if (WARN_ON(timeout == 0)) {
		/* We really should never get here */
		vbg_err("%s: Call timedout and cancellation failed, leaking the request\n",
			__func__);
		*leak_it = true;
		return ret;
	}

	/* The call has completed normally after all */
	return 0;
}

/**
 * Copies the result of the call back to the caller info structure and user
 * buffers.
 *
 * @returns 0 or negative errno value.
 * @param   info                Call info structure to update.
 * @param   call                HGCM call request.
 * @param   bounce_bufs         The bouncebuffer array.
 */
static int hgcm_call_copy_back_result(VBGLIOCHGCMCALL *info,
				      const struct vmmdev_hgcm_call *call,
				      void **bounce_bufs)
{
	const struct hgcm_function_parameter *src_parm =
		VMMDEV_HGCM_CALL_PARMS(call);
	struct hgcm_function_parameter *dst_parm = VBGL_HGCM_CALL_PARMS(info);
	u32 i, parms = info->cParms;
	void __user *userp;
	int ret;

	/* The call result. */
	info->Hdr.rc = call->header.result;

	/* Copy back parameters. */
	for (i = 0; i < parms; i++, src_parm++, dst_parm++) {
		switch (dst_parm->type) {
		case VMMDevHGCMParmType_32bit:
		case VMMDevHGCMParmType_64bit:
			*dst_parm = *src_parm;
			break;

		case VMMDevHGCMParmType_PageList:
			dst_parm->u.PageList.size = src_parm->u.PageList.size;
			break;

		case VMMDevHGCMParmType_LinAddr_In:
			dst_parm->u.Pointer.size = src_parm->u.Pointer.size;
			break;

		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
			dst_parm->u.Pointer.size = src_parm->u.Pointer.size;
			if (!bounce_bufs)
				break; /* In kernel call */

			userp = (void __user *)dst_parm->u.Pointer.u.linearAddr;
			ret = copy_to_user(userp, bounce_bufs[i],
					   min(src_parm->u.Pointer.size,
					       dst_parm->u.Pointer.size));
			if (ret)
				return -EFAULT;
			break;

		default:
			WARN_ON(1);
			return -EINVAL;
		}
	}

	return 0;
}

int vbg_hgcm_call(struct vbg_dev *gdev, VBGLIOCHGCMCALL *info, bool is_user)
{
	struct vmmdev_hgcm_call *call;
	void **bounce_bufs;
	size_t extra_size;
	bool leak_it;
	int i, ret;

	/*
	 * Validate, lock and buffer the parameters for the call.
	 * This will calculate the amount of extra space for physical page list.
	 */
	ret = hgcm_call_preprocess(info, is_user, &bounce_bufs, &extra_size);
	if (ret) {
		/* Even on error bounce bufs may still have been allocated */
		goto free_bounce_bufs;
	}

	call = vbg_req_alloc(sizeof(struct vmmdev_hgcm_call) + info->cParms *
				sizeof(struct hgcm_function_parameter) +
			     extra_size, VMMDevReq_HGCMCall);
	if (!call) {
		ret = -ENOMEM;
		goto free_bounce_bufs;
	}

	hgcm_call_init_call(call, info, bounce_bufs);

	ret = vbg_hgcm_do_call(gdev, call, info, is_user, &leak_it);
	if (ret == 0)
		ret = hgcm_call_copy_back_result(info, call, bounce_bufs);

	if (!leak_it)
		kfree(call);

free_bounce_bufs:
	if (bounce_bufs) {
		for (i = 0; i < info->cParms; i++)
			kvfree(bounce_bufs[i]);
		kfree(bounce_bufs);
	}

	return ret;
}
EXPORT_SYMBOL(vbg_hgcm_call);

#ifdef CONFIG_X86_64
int vbg_hgcm_call32(struct vbg_dev *gdev, VBGLIOCHGCMCALL *info)
{
	VBGLIOCHGCMCALL *info64 = NULL;
	struct hgcm_function_parameter *parm64 = NULL;
	struct hgcm_function_parameter32 *parm32 = NULL;
	u32 i, info64_size, parms = info->cParms;
	int ret = 0;

	/* KISS allocate a temporary request and convert the parameters. */
	info64_size = sizeof(*info64);
	info64_size += parms * sizeof(struct hgcm_function_parameter);
	info64 = kzalloc(info64_size, GFP_KERNEL);
	if (!info64)
		return -ENOMEM;

	*info64 = *info;
	parm32 = VBGL_HGCM_CALL_PARMS32(info);
	parm64 = VBGL_HGCM_CALL_PARMS(info64);
	for (i = 0; i < parms; i++, parm32++, parm64++) {
		switch (parm32->type) {
		case VMMDevHGCMParmType_32bit:
			parm64->type = VMMDevHGCMParmType_32bit;
			parm64->u.value32 = parm32->u.value32;
			break;

		case VMMDevHGCMParmType_64bit:
			parm64->type = VMMDevHGCMParmType_64bit;
			parm64->u.value64 = parm32->u.value64;
			break;

		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
		case VMMDevHGCMParmType_LinAddr_In:
			parm64->type = parm32->type;
			parm64->u.Pointer.size = parm32->u.Pointer.size;
			parm64->u.Pointer.u.linearAddr =
			    parm32->u.Pointer.u.linearAddr;
			break;

		default:
			ret = -EINVAL;
		}
		if (ret < 0)
			goto out_free;
	}

	ret = vbg_hgcm_call(gdev, info64, true);
	if (ret < 0)
		goto out_free;

	/* Copy back. */
	*info = *info64;
	parm32 = VBGL_HGCM_CALL_PARMS32(info);
	parm64 = VBGL_HGCM_CALL_PARMS(info64);
	for (i = 0; i < parms; i++, parm32++, parm64++) {
		switch (parm64->type) {
		case VMMDevHGCMParmType_32bit:
			parm32->u.value32 = parm64->u.value32;
			break;

		case VMMDevHGCMParmType_64bit:
			parm32->u.value64 = parm64->u.value64;
			break;

		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
		case VMMDevHGCMParmType_LinAddr_In:
			parm32->u.Pointer.size = parm64->u.Pointer.size;
			break;

		default:
			WARN_ON(1);
			ret = -EINVAL;
		}
	}

out_free:
	kfree(info64);
	return ret;
}
#endif

int vbg_status_code_to_errno(int rc)
{
	if (rc >= 0)
		return 0;

	switch (rc) {
	case VERR_ACCESS_DENIED:                    return -EPERM;
	case VERR_FILE_NOT_FOUND:                   return -ENOENT;
	case VERR_PROCESS_NOT_FOUND:                return -ESRCH;
	case VERR_INTERRUPTED:                      return -EINTR;
	case VERR_DEV_IO_ERROR:                     return -EIO;
	case VERR_TOO_MUCH_DATA:                    return -E2BIG;
	case VERR_BAD_EXE_FORMAT:                   return -ENOEXEC;
	case VERR_INVALID_HANDLE:                   return -EBADF;
	case VERR_TRY_AGAIN:                        return -EAGAIN;
	case VERR_NO_MEMORY:                        return -ENOMEM;
	case VERR_INVALID_POINTER:                  return -EFAULT;
	case VERR_RESOURCE_BUSY:                    return -EBUSY;
	case VERR_ALREADY_EXISTS:                   return -EEXIST;
	case VERR_NOT_SAME_DEVICE:                  return -EXDEV;
	case VERR_NOT_A_DIRECTORY:
	case VERR_PATH_NOT_FOUND:                   return -ENOTDIR;
	case VERR_IS_A_DIRECTORY:                   return -EISDIR;
	case VERR_INVALID_PARAMETER:                return -EINVAL;
	case VERR_TOO_MANY_OPEN_FILES:              return -ENFILE;
	case VERR_INVALID_FUNCTION:                 return -ENOTTY;
	case VERR_SHARING_VIOLATION:                return -ETXTBSY;
	case VERR_FILE_TOO_BIG:                     return -EFBIG;
	case VERR_DISK_FULL:                        return -ENOSPC;
	case VERR_SEEK_ON_DEVICE:                   return -ESPIPE;
	case VERR_WRITE_PROTECT:                    return -EROFS;
	case VERR_BROKEN_PIPE:                      return -EPIPE;
	case VERR_DEADLOCK:                         return -EDEADLK;
	case VERR_FILENAME_TOO_LONG:                return -ENAMETOOLONG;
	case VERR_FILE_LOCK_FAILED:                 return -ENOLCK;
	case VERR_NOT_IMPLEMENTED:
	case VERR_NOT_SUPPORTED:                    return -ENOSYS;
	case VERR_DIR_NOT_EMPTY:                    return -ENOTEMPTY;
	case VERR_TOO_MANY_SYMLINKS:                return -ELOOP;
	case VERR_NO_DATA:                          return -ENODATA;
	case VERR_NET_NO_NETWORK:                   return -ENONET;
	case VERR_NET_NOT_UNIQUE_NAME:              return -ENOTUNIQ;
	case VERR_NO_TRANSLATION:                   return -EILSEQ;
	case VERR_NET_NOT_SOCKET:                   return -ENOTSOCK;
	case VERR_NET_DEST_ADDRESS_REQUIRED:        return -EDESTADDRREQ;
	case VERR_NET_MSG_SIZE:                     return -EMSGSIZE;
	case VERR_NET_PROTOCOL_TYPE:                return -EPROTOTYPE;
	case VERR_NET_PROTOCOL_NOT_AVAILABLE:       return -ENOPROTOOPT;
	case VERR_NET_PROTOCOL_NOT_SUPPORTED:       return -EPROTONOSUPPORT;
	case VERR_NET_SOCKET_TYPE_NOT_SUPPORTED:    return -ESOCKTNOSUPPORT;
	case VERR_NET_OPERATION_NOT_SUPPORTED:      return -EOPNOTSUPP;
	case VERR_NET_PROTOCOL_FAMILY_NOT_SUPPORTED: return -EPFNOSUPPORT;
	case VERR_NET_ADDRESS_FAMILY_NOT_SUPPORTED: return -EAFNOSUPPORT;
	case VERR_NET_ADDRESS_IN_USE:               return -EADDRINUSE;
	case VERR_NET_ADDRESS_NOT_AVAILABLE:        return -EADDRNOTAVAIL;
	case VERR_NET_DOWN:                         return -ENETDOWN;
	case VERR_NET_UNREACHABLE:                  return -ENETUNREACH;
	case VERR_NET_CONNECTION_RESET:             return -ENETRESET;
	case VERR_NET_CONNECTION_ABORTED:           return -ECONNABORTED;
	case VERR_NET_CONNECTION_RESET_BY_PEER:     return -ECONNRESET;
	case VERR_NET_NO_BUFFER_SPACE:              return -ENOBUFS;
	case VERR_NET_ALREADY_CONNECTED:            return -EISCONN;
	case VERR_NET_NOT_CONNECTED:                return -ENOTCONN;
	case VERR_NET_SHUTDOWN:                     return -ESHUTDOWN;
	case VERR_NET_TOO_MANY_REFERENCES:          return -ETOOMANYREFS;
	case VERR_TIMEOUT:                          return -ETIMEDOUT;
	case VERR_NET_CONNECTION_REFUSED:           return -ECONNREFUSED;
	case VERR_NET_HOST_DOWN:                    return -EHOSTDOWN;
	case VERR_NET_HOST_UNREACHABLE:             return -EHOSTUNREACH;
	case VERR_NET_ALREADY_IN_PROGRESS:          return -EALREADY;
	case VERR_NET_IN_PROGRESS:                  return -EINPROGRESS;
	case VERR_MEDIA_NOT_PRESENT:                return -ENOMEDIUM;
	case VERR_MEDIA_NOT_RECOGNIZED:             return -EMEDIUMTYPE;
	default:
		vbg_warn("%s: Unhandled err %d\n", __func__, rc);
		return -EPROTO;
	}
}
EXPORT_SYMBOL(vbg_status_code_to_errno);
