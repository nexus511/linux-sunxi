/*
 * vboxguest core guest-device handling code, VBoxGuest.cpp in upstream svn.
 *
 * Copyright (C) 2007-2016 Oracle Corporation
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

#include <linux/device.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/vbox_err.h>
#include <linux/vbox_utils.h>
#include <linux/vmalloc.h>
#include "vboxguest_core.h"
#include "vboxguest_version.h"

#define GUEST_MAPPINGS_TRIES	5

/**
 * Reserves memory in which the VMM can relocate any guest mappings
 * that are floating around.
 *
 * This operation is a little bit tricky since the VMM might not accept
 * just any address because of address clashes between the three contexts
 * it operates in, so we try several times.
 *
 * Failure to reserve the guest mappings is ignored.
 *
 * @param   gdev	The Guest extension device.
 */
static void vbg_guest_mappings_init(struct vbg_dev *gdev)
{
	struct vmmdev_hypervisorinfo *req;
	void *guest_mappings[GUEST_MAPPINGS_TRIES];
	struct page **pages = NULL;
	u32 size, hypervisor_size;
	int i, rc;

	/* Query the required space. */
	req = vbg_req_alloc(sizeof(*req), VMMDevReq_GetHypervisorInfo);
	if (!req)
		return;

	req->hypervisorStart = 0;
	req->hypervisorSize = 0;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		goto out;

	/*
	 * The VMM will report back if there is nothing it wants to map, like
	 * for instance in VT-x and AMD-V mode.
	 */
	if (req->hypervisorSize == 0)
		goto out;

	hypervisor_size = req->hypervisorSize;
	/* Add 4M so that we can align the vmap to 4MiB as the host requires. */
	size = PAGE_ALIGN(req->hypervisorSize) + SZ_4M;

	pages = kmalloc(sizeof(*pages) * (size >> PAGE_SHIFT), GFP_KERNEL);
	if (!pages)
		goto out;

	gdev->guest_mappings_dummy_page = alloc_page(GFP_HIGHUSER);
	if (!gdev->guest_mappings_dummy_page)
		goto out;

	for (i = 0; i < (size >> PAGE_SHIFT); i++)
		pages[i] = gdev->guest_mappings_dummy_page;

	/* Try several times, the host can be picky about certain addresses. */
	for (i = 0; i < GUEST_MAPPINGS_TRIES; i++) {
		guest_mappings[i] = vmap(pages, (size >> PAGE_SHIFT),
					 VM_MAP, PAGE_KERNEL_RO);
		if (!guest_mappings[i])
			break;

		req->header.requestType = VMMDevReq_SetHypervisorInfo;
		req->header.rc = VERR_INTERNAL_ERROR;
		req->hypervisorSize = hypervisor_size;
		req->hypervisorStart =
			(unsigned long)PTR_ALIGN(guest_mappings[i], SZ_4M);

		rc = vbg_req_perform(gdev, req);
		if (rc >= 0) {
			gdev->guest_mappings = guest_mappings[i];
			break;
		}
	}

	/* Free vmap's from failed attempts. */
	while (--i >= 0)
		vunmap(guest_mappings[i]);

	/* On failure free the dummy-page backing the vmap */
	if (!gdev->guest_mappings) {
		__free_page(gdev->guest_mappings_dummy_page);
		gdev->guest_mappings_dummy_page = NULL;
	}

out:
	kfree(req);
	kfree(pages);
}

/**
 * Undo what vbg_guest_mappings_init did.
 *
 * @param   gdev	The Guest extension device.
 */
static void vbg_guest_mappings_exit(struct vbg_dev *gdev)
{
	struct vmmdev_hypervisorinfo *req;
	int rc;

	if (!gdev->guest_mappings)
		return;

	/*
	 * Tell the host that we're going to free the memory we reserved for
	 * it, the free it up. (Leak the memory if anything goes wrong here.)
	 */
	req = vbg_req_alloc(sizeof(*req), VMMDevReq_SetHypervisorInfo);
	if (!req)
		return;

	req->hypervisorStart = 0;
	req->hypervisorSize = 0;

	rc = vbg_req_perform(gdev, req);

	kfree(req);

	if (rc < 0) {
		vbg_err("%s error: %d\n", __func__, rc);
		return;
	}

	vunmap(gdev->guest_mappings);
	gdev->guest_mappings = NULL;

	__free_page(gdev->guest_mappings_dummy_page);
	gdev->guest_mappings_dummy_page = NULL;
}

/**
 * Report the guest information to the host.
 *
 * @returns 0 or negative errno value.
 * @param   gdev	The Guest extension device.
 */
static int vbg_report_guest_info(struct vbg_dev *gdev)
{
	/*
	 * Allocate and fill in the two guest info reports.
	 */
	struct vmmdev_guest_info *req1 = NULL;
	struct vmmdev_guest_info2 *req2 = NULL;
	int rc, ret = -ENOMEM;

	req1 = vbg_req_alloc(sizeof(*req1), VMMDevReq_ReportGuestInfo);
	req2 = vbg_req_alloc(sizeof(*req2), VMMDevReq_ReportGuestInfo2);
	if (!req1 || !req2)
		goto out_free;

	req1->interfaceVersion = VMMDEV_VERSION;
	req1->osType = VBOXOSTYPE_Linux26;
#if __BITS_PER_LONG == 64
	req1->osType |= VBOXOSTYPE_x64;
#endif

	req2->additionsMajor = VBOX_VERSION_MAJOR;
	req2->additionsMinor = VBOX_VERSION_MINOR;
	req2->additionsBuild = VBOX_VERSION_BUILD;
	req2->additionsRevision = VBOX_SVN_REV;
	/* (no features defined yet) */
	req2->additionsFeatures = 0;
	strlcpy(req2->szName, VBOX_VERSION_STRING,
		sizeof(req2->szName));

	/*
	 * There are two protocols here:
	 *      1. Info2 + Info1. Supported by >=3.2.51.
	 *      2. Info1 and optionally Info2. The old protocol.
	 *
	 * We try protocol 2 first.  It will fail with VERR_NOT_SUPPORTED
	 * if not supported by the VMMDev (message ordering requirement).
	 */
	rc = vbg_req_perform(gdev, req2);
	if (rc >= 0) {
		rc = vbg_req_perform(gdev, req1);
	} else if (rc == VERR_NOT_SUPPORTED || rc == VERR_NOT_IMPLEMENTED) {
		rc = vbg_req_perform(gdev, req1);
		if (rc >= 0) {
			rc = vbg_req_perform(gdev, req2);
			if (rc == VERR_NOT_IMPLEMENTED)
				rc = VINF_SUCCESS;
		}
	}
	ret = vbg_status_code_to_errno(rc);

out_free:
	kfree(req2);
	kfree(req1);
	return ret;
}

/**
 * Report the guest driver status to the host.
 *
 * @returns 0 or negative errno value.
 * @param   gdev	The Guest extension device.
 * @param   active	Flag whether the driver is now active or not.
 */
static int vbg_report_driver_status(struct vbg_dev *gdev, bool active)
{
	struct vmmdev_guest_status *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_ReportGuestStatus);
	if (!req)
		return -ENOMEM;

	req->facility = VBoxGuestFacilityType_VBoxGuestDriver;
	req->status = active ? VBoxGuestFacilityStatus_Active :
					   VBoxGuestFacilityStatus_Inactive;
	req->flags = 0;

	rc = vbg_req_perform(gdev, req);
	if (rc == VERR_NOT_IMPLEMENTED)	/* Compatibility with older hosts. */
		rc = VINF_SUCCESS;

	kfree(req);

	return vbg_status_code_to_errno(rc);
}

/** @name Memory Ballooning
 * @{
 */

/**
 * Inflate the balloon by one chunk.
 *
 * The caller owns the balloon mutex.
 *
 * @returns 0 or negative errno value.
 * @param   gdev	The Guest extension device.
 * @param   chunk_idx	Index of the chunk.
 */
static int vbg_balloon_inflate(struct vbg_dev *gdev, u32 chunk_idx)
{
	struct vmmdev_memballoon_change *req = gdev->mem_balloon.change_req;
	struct page **pages;
	int i, rc, ret;

	pages = kmalloc(sizeof(*pages) * VMMDEV_MEMORY_BALLOON_CHUNK_PAGES,
			GFP_KERNEL | __GFP_NOWARN);
	if (!pages)
		return -ENOMEM;

	req->header.size = sizeof(*req);
	req->inflate = true;
	req->pages = VMMDEV_MEMORY_BALLOON_CHUNK_PAGES;

	for (i = 0; i < VMMDEV_MEMORY_BALLOON_CHUNK_PAGES; i++) {
		pages[i] = alloc_page(GFP_KERNEL | __GFP_NOWARN);
		if (!pages[i]) {
			ret = -ENOMEM;
			goto out_error;
		}

		req->phys_page[i] = page_to_phys(pages[i]);
	}

	rc = vbg_req_perform(gdev, req);
	if (rc < 0) {
		vbg_err("%s error, rc: %d\n", __func__, rc);
		ret = vbg_status_code_to_errno(rc);
		goto out_error;
	}

	gdev->mem_balloon.pages[chunk_idx] = pages;

	return 0;

out_error:
	while (--i >= 0)
		__free_page(pages[i]);
	kfree(pages);

	return ret;
}

/**
 * Deflate the balloon by one chunk.
 *
 * The caller owns the balloon mutex.
 *
 * @returns 0 or negative errno value.
 * @param   gdev	The Guest extension device.
 * @param   chunk_idx	Index of the chunk.
 */
static int vbg_balloon_deflate(struct vbg_dev *gdev, u32 chunk_idx)
{
	struct vmmdev_memballoon_change *req = gdev->mem_balloon.change_req;
	struct page **pages = gdev->mem_balloon.pages[chunk_idx];
	int i, rc;

	req->header.size = sizeof(*req);
	req->inflate = false;
	req->pages = VMMDEV_MEMORY_BALLOON_CHUNK_PAGES;

	for (i = 0; i < VMMDEV_MEMORY_BALLOON_CHUNK_PAGES; i++)
		req->phys_page[i] = page_to_phys(pages[i]);

	rc = vbg_req_perform(gdev, req);
	if (rc < 0) {
		vbg_err("%s error, rc: %d\n", __func__, rc);
		return vbg_status_code_to_errno(rc);
	}

	for (i = 0; i < VMMDEV_MEMORY_BALLOON_CHUNK_PAGES; i++)
		__free_page(pages[i]);
	kfree(pages);
	gdev->mem_balloon.pages[chunk_idx] = NULL;

	return 0;
}

/**
 * Respond to VMMDEV_EVENT_BALLOON_CHANGE_REQUEST events, query the size
 * the host wants the balloon to be and adjust accordingly.
 */
static void vbg_balloon_work(struct work_struct *work)
{
	struct vbg_dev *gdev =
		container_of(work, struct vbg_dev, mem_balloon.work);
	struct vmmdev_memballoon_info *req = gdev->mem_balloon.get_req;
	u32 i, chunks;
	int rc, ret;

	/*
	 * Setting this bit means that we request the value from the host and
	 * change the guest memory balloon according to the returned value.
	 */
	req->eventAck = VMMDEV_EVENT_BALLOON_CHANGE_REQUEST;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0) {
		vbg_err("%s error, rc: %d)\n", __func__, rc);
		return;
	}

	/*
	 * The host always returns the same maximum amount of chunks, so
	 * we do this once.
	 */
	if (!gdev->mem_balloon.max_chunks) {
		gdev->mem_balloon.pages =
			devm_kcalloc(gdev->dev, req->cPhysMemChunks,
				     sizeof(struct page **), GFP_KERNEL);
		if (!gdev->mem_balloon.pages)
			return;

		gdev->mem_balloon.max_chunks = req->cPhysMemChunks;
	}

	chunks = req->cBalloonChunks;
	if (chunks > gdev->mem_balloon.max_chunks) {
		vbg_err("%s: illegal balloon size %u (max=%u)\n",
			__func__, chunks, gdev->mem_balloon.max_chunks);
		return;
	}

	if (req->cBalloonChunks > gdev->mem_balloon.chunks) {
		/* inflate */
		for (i = gdev->mem_balloon.chunks; i < chunks; i++) {
			ret = vbg_balloon_inflate(gdev, i);
			if (ret < 0)
				return;

			gdev->mem_balloon.chunks++;
		}
	} else {
		/* deflate */
		for (i = gdev->mem_balloon.chunks; i-- > chunks;) {
			ret = vbg_balloon_deflate(gdev, i);
			if (ret < 0)
				return;

			gdev->mem_balloon.chunks--;
		}
	}
}

/** @} */

/** @name Heartbeat
 * @{
 */

/**
 * Callback for heartbeat timer.
 */
static void vbg_heartbeat_timer(unsigned long data)
{
	struct vbg_dev *gdev = (struct vbg_dev *)data;

	vbg_req_perform(gdev, gdev->guest_heartbeat_req);
	mod_timer(&gdev->heartbeat_timer,
		  msecs_to_jiffies(gdev->heartbeat_interval_ms));
}

/**
 * Configure the host to check guest's heartbeat
 * and get heartbeat interval from the host.
 *
 * @returns 0 or negative errno value.
 * @param   gdev	The Guest extension device.
 * @param   enabled	Set true to enable guest heartbeat checks on host.
 */
static int vbg_heartbeat_host_config(struct vbg_dev *gdev, bool enabled)
{
	struct vmmdev_heartbeat *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_HeartbeatConfigure);
	if (!req)
		return -ENOMEM;

	req->fEnabled = enabled;
	req->cNsInterval = 0;
	rc = vbg_req_perform(gdev, req);
	do_div(req->cNsInterval, 1000000); /* ns -> ms */
	gdev->heartbeat_interval_ms = req->cNsInterval;
	kfree(req);

	return vbg_status_code_to_errno(rc);
}

/**
 * Initializes the heartbeat timer.
 *
 * This feature may be disabled by the host.
 *
 * @returns 0 or negative errno value (ignored).
 * @param   gdev	The Guest extension device.
 */
static int vbg_heartbeat_init(struct vbg_dev *gdev)
{
	int ret;

	/* Make sure that heartbeat checking is disabled if we fail. */
	ret = vbg_heartbeat_host_config(gdev, false);
	if (ret < 0)
		return ret;

	ret = vbg_heartbeat_host_config(gdev, true);
	if (ret < 0)
		return ret;

	/*
	 * Preallocate the request to use it from the timer callback because:
	 *    1) on Windows vbg_req_alloc must be called at IRQL <= APC_LEVEL
	 *       and the timer callback runs at DISPATCH_LEVEL;
	 *    2) avoid repeated allocations.
	 */
	gdev->guest_heartbeat_req = vbg_req_alloc(
					sizeof(*gdev->guest_heartbeat_req),
					VMMDevReq_GuestHeartbeat);
	if (!gdev->guest_heartbeat_req)
		return -ENOMEM;

	vbg_info("%s: Setting up heartbeat to trigger every %d milliseconds\n",
		 __func__, gdev->heartbeat_interval_ms);
	mod_timer(&gdev->heartbeat_timer, 0);

	return 0;
}

/**
 * Cleanup hearbeat code, stop HB timer and disable host heartbeat checking.
 * @param   gdev	The Guest extension device.
 */
static void vbg_heartbeat_exit(struct vbg_dev *gdev)
{
	del_timer_sync(&gdev->heartbeat_timer);
	vbg_heartbeat_host_config(gdev, false);
	kfree(gdev->guest_heartbeat_req);

}

/** @} */

/** @name Guest Capabilities and Event Filter
 * @{
 */

/**
 * Applies a change to the bit usage tracker.
 *
 * @returns true if the mask changed, false if not.
 * @param   tracker	The bit usage tracker.
 * @param   changed	The bits to change.
 * @param   previous	The previous value of the bits.
 */
static bool vbg_track_bit_usage(struct vbg_bit_usage_tracker *tracker,
				u32 changed, u32 previous)
{
	bool global_change = false;

	while (changed) {
		u32 bit = ffs(changed) - 1;
		u32 bitmask = BIT(bit);

		if (bitmask & previous) {
			tracker->per_bit_usage[bit] -= 1;
			if (tracker->per_bit_usage[bit] == 0) {
				global_change = true;
				tracker->mask &= ~bitmask;
			}
		} else {
			tracker->per_bit_usage[bit] += 1;
			if (tracker->per_bit_usage[bit] == 1) {
				global_change = true;
				tracker->mask |= bitmask;
			}
		}

		changed &= ~bitmask;
	}

	return global_change;
}

/**
 * Init and termination worker for resetting the (host) event filter on the host
 *
 * @returns 0 or negative errno value.
 * @param   gdev            The Guest extension device.
 * @param   fixed_events    Fixed events (init time).
 */
static int vbg_reset_host_event_filter(struct vbg_dev *gdev,
				       u32 fixed_events)
{
	struct vmmdev_mask *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_CtlGuestFilterMask);
	if (!req)
		return -ENOMEM;

	req->u32NotMask = U32_MAX & ~fixed_events;
	req->u32OrMask = fixed_events;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		vbg_err("%s error, rc: %d\n", __func__, rc);

	kfree(req);
	return vbg_status_code_to_errno(rc);
}

/**
 * Changes the event filter mask for the given session.
 *
 * This is called in response to VBGL_IOCTL_CHANGE_FILTER_MASK as well as to
 * do session cleanup.
 *
 * @returns 0 or negative errno value.
 * @param   gdev                The Guest extension device.
 * @param   session             The session.
 * @param   or_mask             The events to add.
 * @param   not_mask            The events to remove.
 * @param   session_termination Set if we're called by the session cleanup code.
 *                              This tweaks the error handling so we perform
 *                              proper session cleanup even if the host
 *                              misbehaves.
 *
 * @remarks Takes the session spinlock.
 */
static int vbg_set_session_event_filter(struct vbg_dev *gdev,
					struct vbg_session *session,
					u32 or_mask, u32 not_mask,
					bool session_termination)
{
	struct vmmdev_mask *req;
	u32 changed, previous;
	unsigned long flags;
	int rc, ret = 0;

	/* Allocate a request buffer before taking the spinlock */
	req = vbg_req_alloc(sizeof(*req), VMMDevReq_CtlGuestFilterMask);
	if (!req) {
		if (!session_termination)
			return -ENOMEM;
		/* Ignore failure, we must do session cleanup. */
	}

	spin_lock_irqsave(&gdev->session_spinlock, flags);

	/* Apply the changes to the session mask. */
	previous = session->event_filter;
	session->event_filter |= or_mask;
	session->event_filter &= ~not_mask;

	/* If anything actually changed, update the global usage counters. */
	changed = previous ^ session->event_filter;
	if (!changed)
		goto out;

	vbg_track_bit_usage(&gdev->event_filter_tracker, changed, previous);
	req->u32OrMask = gdev->fixed_events | gdev->event_filter_tracker.mask;

	if (gdev->event_filter_host == req->u32OrMask || !req)
		goto out;

	gdev->event_filter_host = req->u32OrMask;
	req->u32NotMask = ~req->u32OrMask;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0) {
		ret = vbg_status_code_to_errno(rc);

		/* Failed, roll back (unless it's session termination time). */
		gdev->event_filter_host = U32_MAX;
		if (session_termination)
			goto out;

		vbg_track_bit_usage(&gdev->event_filter_tracker, changed,
				    session->event_filter);
		session->event_filter = previous;
	}

out:
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);
	kfree(req);

	return ret;
}

/**
 * Init and termination worker for set guest capabilities to zero on the host.
 *
 * @returns 0 or negative errno value.
 * @param   gdev	The Guest extension device.
 */
static int vbg_reset_host_capabilities(struct vbg_dev *gdev)
{
	struct vmmdev_mask *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_SetGuestCapabilities);
	if (!req)
		return -ENOMEM;

	req->u32NotMask = U32_MAX;
	req->u32OrMask = 0;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		vbg_err("%s error, rc: %d\n", __func__, rc);

	kfree(req);
	return vbg_status_code_to_errno(rc);
}

/**
 * Sets the guest capabilities for a session.
 *
 * @returns 0 or negative errno value.
 * @param   gdev                The Guest extension device.
 * @param   session             The session.
 * @param   or_mask             The capabilities to add.
 * @param   not_mask            The capabilities to remove.
 * @param   session_termination Set if we're called by the session cleanup code.
 *                              This tweaks the error handling so we perform
 *                              proper session cleanup even if the host
 *                              misbehaves.
 *
 * @remarks Takes the session spinlock.
 */
static int vbg_set_session_capabilities(struct vbg_dev *gdev,
					struct vbg_session *session,
					u32 or_mask, u32 not_mask,
					bool session_termination)
{
	struct vmmdev_mask *req;
	unsigned long flags;
	u32 changed, previous;
	int rc, ret = 0;

	/* Allocate a request buffer before taking the spinlock */
	req = vbg_req_alloc(sizeof(*req), VMMDevReq_SetGuestCapabilities);
	if (!req) {
		if (!session_termination)
			return -ENOMEM;
		/* Ignore failure, we must do session cleanup. */
	}

	spin_lock_irqsave(&gdev->session_spinlock, flags);

	/* Apply the changes to the session mask. */
	previous = session->guest_caps;
	session->guest_caps |= or_mask;
	session->guest_caps &= ~not_mask;

	/* If anything actually changed, update the global usage counters. */
	changed = previous ^ session->guest_caps;
	if (!changed)
		goto out;

	vbg_track_bit_usage(&gdev->guest_caps_tracker, changed, previous);
	req->u32OrMask = gdev->guest_caps_tracker.mask;

	if (gdev->guest_caps_host == req->u32OrMask || !req)
		goto out;

	gdev->guest_caps_host = req->u32OrMask;
	req->u32NotMask = ~req->u32OrMask;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0) {
		ret = vbg_status_code_to_errno(rc);

		/* Failed, roll back (unless it's session termination time). */
		gdev->guest_caps_host = U32_MAX;
		if (session_termination)
			goto out;

		vbg_track_bit_usage(&gdev->guest_caps_tracker, changed,
				    session->guest_caps);
		session->guest_caps = previous;
	}

out:
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);
	kfree(req);

	return ret;
}

/** @} */

/**
 * vbg_query_host_version try get the host feature mask and version information
 * (vbg_host_version).
 *
 * @returns 0 or negative errno value (ignored).
 * @param   gdev	The Guest extension device.
 */
static int vbg_query_host_version(struct vbg_dev *gdev)
{
	struct vmmdev_host_version *req;
	int rc, ret;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_GetHostVersion);
	if (!req)
		return -ENOMEM;

	rc = vbg_req_perform(gdev, req);
	ret = vbg_status_code_to_errno(rc);
	if (ret)
		goto out;

	snprintf(gdev->host_version, sizeof(gdev->host_version), "%u.%u.%ur%u",
		 req->major, req->minor, req->build, req->revision);
	gdev->host_features = req->features;

	vbg_info("vboxguest: host-version: %s %#x\n", gdev->host_version,
		 gdev->host_features);

	if (!(req->features & VMMDEV_HVF_HGCM_PHYS_PAGE_LIST)) {
		vbg_err("vboxguest: Error host too old (does not support page-lists)\n");
		ret = -ENODEV;
	}

out:
	kfree(req);
	return ret;
}

/**
 * Initializes the VBoxGuest device extension when the
 * device driver is loaded.
 *
 * The native code locates the VMMDev on the PCI bus and retrieve
 * the MMIO and I/O port ranges, this function will take care of
 * mapping the MMIO memory (if present). Upon successful return
 * the native code should set up the interrupt handler.
 *
 * @returns 0 or negative errno value.
 *
 * @param   gdev           The Guest extension device.
 * @param   fixed_events   Events that will be enabled upon init and no client
 *                         will ever be allowed to mask.
 */
int vbg_core_init(struct vbg_dev *gdev, u32 fixed_events)
{
	int ret = -ENOMEM;

	gdev->fixed_events = fixed_events | VMMDEV_EVENT_HGCM;
	gdev->event_filter_host = U32_MAX;	/* forces a report */
	gdev->guest_caps_host = U32_MAX;	/* forces a report */

	init_waitqueue_head(&gdev->event_wq);
	init_waitqueue_head(&gdev->hgcm_wq);
	INIT_LIST_HEAD(&gdev->session_list);
	spin_lock_init(&gdev->event_spinlock);
	spin_lock_init(&gdev->session_spinlock);
	mutex_init(&gdev->cancel_req_mutex);
	setup_timer(&gdev->heartbeat_timer, vbg_heartbeat_timer,
		    (unsigned long)gdev);
	INIT_WORK(&gdev->mem_balloon.work, vbg_balloon_work);

	gdev->mem_balloon.get_req =
		vbg_req_alloc(sizeof(*gdev->mem_balloon.get_req),
			      VMMDevReq_GetMemBalloonChangeRequest);
	gdev->mem_balloon.change_req =
		vbg_req_alloc(sizeof(*gdev->mem_balloon.change_req),
			      VMMDevReq_ChangeMemBalloon);
	gdev->cancel_req =
		vbg_req_alloc(sizeof(*(gdev->cancel_req)),
			      VMMDevReq_HGCMCancel2);
	gdev->ack_events_req =
		vbg_req_alloc(sizeof(*gdev->ack_events_req),
			      VMMDevReq_AcknowledgeEvents);
	gdev->mouse_status_req =
		vbg_req_alloc(sizeof(*gdev->mouse_status_req),
			      VMMDevReq_GetMouseStatus);

	if (!gdev->mem_balloon.get_req || !gdev->mem_balloon.change_req ||
	    !gdev->cancel_req || !gdev->ack_events_req ||
	    !gdev->mouse_status_req)
		goto err_free_reqs;

	ret = vbg_query_host_version(gdev);
	if (ret)
		goto err_free_reqs;

	ret = vbg_report_guest_info(gdev);
	if (ret) {
		vbg_err("vboxguest: vbg_report_guest_info error: %d\n", ret);
		goto err_free_reqs;
	}

	ret = vbg_reset_host_event_filter(gdev, gdev->fixed_events);
	if (ret) {
		vbg_err("vboxguest: Error setting fixed event filter: %d\n",
			ret);
		goto err_free_reqs;
	}

	ret = vbg_reset_host_capabilities(gdev);
	if (ret) {
		vbg_err("vboxguest: Error clearing guest capabilities: %d\n",
			ret);
		goto err_free_reqs;
	}

	ret = vbg_core_set_mouse_status(gdev, 0);
	if (ret) {
		vbg_err("vboxguest: Error clearing mouse status: %d\n", ret);
		goto err_free_reqs;
	}

	/* These may fail without requiring the driver init to fail. */
	vbg_guest_mappings_init(gdev);
	vbg_heartbeat_init(gdev);

	/* All Done! */
	ret = vbg_report_driver_status(gdev, true);
	if (ret < 0)
		vbg_err("vboxguest: VBoxReportGuestDriverStatus error: %d\n",
			ret);

	return 0;

err_free_reqs:
	kfree(gdev->mouse_status_req);
	kfree(gdev->ack_events_req);
	kfree(gdev->cancel_req);
	kfree(gdev->mem_balloon.change_req);
	kfree(gdev->mem_balloon.get_req);
	return ret;
}

/**
 * Call this on exit to clean-up vboxguest-core managed resources.
 *
 * The native code should call this before the driver is loaded,
 * but don't call this on shutdown.
 *
 * @param   gdev	The Guest extension device.
 */
void vbg_core_exit(struct vbg_dev *gdev)
{
	vbg_heartbeat_exit(gdev);
	vbg_guest_mappings_exit(gdev);

	/* Clear the host flags (mouse status etc). */
	vbg_reset_host_event_filter(gdev, 0);
	vbg_reset_host_capabilities(gdev);
	vbg_core_set_mouse_status(gdev, 0);

	kfree(gdev->mouse_status_req);
	kfree(gdev->ack_events_req);
	kfree(gdev->cancel_req);
	kfree(gdev->mem_balloon.change_req);
	kfree(gdev->mem_balloon.get_req);
}

/**
 * Creates a VBoxGuest user session.
 *
 * vboxguest_linux.c calls this when userspace opens the char-device.
 *
 * @returns 0 or negative errno value.
 * @param   gdev          The Guest extension device.
 * @param   session_ret   Where to store the session on success.
 * @param   user_session  Set if this is a session for the vboxuser device.
 */
int vbg_core_open_session(struct vbg_dev *gdev,
			  struct vbg_session **session_ret, bool user_session)
{
	struct vbg_session *session;
	unsigned long flags;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;

	session->gdev = gdev;
	session->user_session = user_session;

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	list_add(&session->list_node, &gdev->session_list);
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	*session_ret = session;

	return 0;
}

/**
 * Closes a VBoxGuest session.
 *
 * @param   session	The session to close (and free).
 */
void vbg_core_close_session(struct vbg_session *session)
{
	struct vbg_dev *gdev = session->gdev;
	unsigned long flags;
	int i, rc;

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	list_del(&session->list_node);
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	vbg_set_session_capabilities(gdev, session, 0, U32_MAX, true);
	vbg_set_session_event_filter(gdev, session, 0, U32_MAX, true);

	for (i = 0; i < ARRAY_SIZE(session->hgcm_client_ids); i++) {
		if (!session->hgcm_client_ids[i])
			continue;

		vbg_hgcm_disconnect(gdev, session->hgcm_client_ids[i], &rc);
	}

	kfree(session);
}

static int vbg_ioctl_chk(VBGLREQHDR *hdr, size_t in_size, size_t out_size)
{
	if (hdr->cbIn  != (sizeof(*hdr) + in_size) ||
	    hdr->cbOut != (sizeof(*hdr) + out_size))
		return -EINVAL;

	return 0;
}

static int vbg_ioctl_driver_version_info(VBGLIOCDRIVERVERSIONINFO *info)
{
	const u16 vbg_maj_version = VBGL_IOC_VERSION >> 16;
	u16 min_maj_version, req_maj_version;

	if (vbg_ioctl_chk(&info->Hdr, sizeof(info->u.In), sizeof(info->u.Out)))
		return -EINVAL;

	req_maj_version = info->u.In.uReqVersion >> 16;
	min_maj_version = info->u.In.uMinVersion >> 16;

	if (info->u.In.uMinVersion > info->u.In.uReqVersion ||
	    min_maj_version != req_maj_version)
		return -EINVAL;

	if (info->u.In.uMinVersion <= VBGL_IOC_VERSION &&
	    min_maj_version == vbg_maj_version) {
		info->u.Out.uSessionVersion = VBGL_IOC_VERSION;
	} else {
		info->u.Out.uSessionVersion = U32_MAX;
		info->Hdr.rc = VERR_VERSION_MISMATCH;
	}

	info->u.Out.uDriverVersion  = VBGL_IOC_VERSION;
	info->u.Out.uDriverRevision = 0;
	info->u.Out.uReserved1      = 0;
	info->u.Out.uReserved2      = 0;

	return 0;
}

static bool vbg_wait_event_cond(struct vbg_dev *gdev,
				struct vbg_session *session,
				u32 event_mask)
{
	unsigned long flags;
	bool wakeup;
	u32 events;

	spin_lock_irqsave(&gdev->event_spinlock, flags);

	events = gdev->pending_events & event_mask;
	wakeup = events || session->cancel_waiters;

	spin_unlock_irqrestore(&gdev->event_spinlock, flags);

	return wakeup;
}

/* Must be called with the event_lock held */
static u32 vbg_consume_events_locked(struct vbg_dev *gdev,
				     struct vbg_session *session,
				     u32 event_mask)
{
	u32 events = gdev->pending_events & event_mask;

	gdev->pending_events &= ~events;
	return events;
}

static int vbg_ioctl_wait_for_events(struct vbg_dev *gdev,
				     struct vbg_session *session,
				     VBGLIOCWAITFOREVENTS *wait)
{
	u32 timeout_ms = wait->u.In.cMsTimeOut;
	u32 event_mask = wait->u.In.fEvents;
	unsigned long flags;
	long timeout;
	int ret = 0;

	if (vbg_ioctl_chk(&wait->Hdr, sizeof(wait->u.In), sizeof(wait->u.Out)))
		return -EINVAL;

	if (timeout_ms == U32_MAX)
		timeout = MAX_SCHEDULE_TIMEOUT;
	else
		timeout = msecs_to_jiffies(timeout_ms);

	wait->u.Out.fEvents = 0;
	do {
		timeout = wait_event_interruptible_timeout(
				gdev->event_wq,
				vbg_wait_event_cond(gdev, session, event_mask),
				timeout);

		spin_lock_irqsave(&gdev->event_spinlock, flags);

		if (timeout < 0 || session->cancel_waiters) {
			ret = -EINTR;
		} else if (timeout == 0) {
			ret = -ETIMEDOUT;
		} else {
			wait->u.Out.fEvents =
			   vbg_consume_events_locked(gdev, session, event_mask);
		}

		spin_unlock_irqrestore(&gdev->event_spinlock, flags);

		/*
		 * Someone else may have consumed the event(s) first, in
		 * which case we go back to waiting.
		 */
	} while (ret == 0 && wait->u.Out.fEvents == 0);

	return ret;
}

static int vbg_ioctl_interrupt_all_wait_events(struct vbg_dev *gdev,
					       struct vbg_session *session,
					       VBGLREQHDR *hdr)
{
	unsigned long flags;

	if (hdr->cbIn != sizeof(*hdr) || hdr->cbOut != sizeof(*hdr))
		return -EINVAL;

	spin_lock_irqsave(&gdev->event_spinlock, flags);
	session->cancel_waiters = true;
	spin_unlock_irqrestore(&gdev->event_spinlock, flags);

	wake_up(&gdev->event_wq);

	return 0;
}

/**
 * Checks if the VMM request is allowed in the context of the given session.
 *
 * @returns 0 or negative errno value.
 * @param   gdev	The Guest extension device.
 * @param   session	The calling session.
 * @param   req		The request.
 */
static int vbg_req_allowed(struct vbg_dev *gdev, struct vbg_session *session,
			   const struct vmmdev_request_header *req)
{
	const struct vmmdev_guest_status *guest_status;
	bool trusted_apps_only;

	switch (req->requestType) {
	/* Trusted users apps only. */
	case VMMDevReq_QueryCredentials:
	case VMMDevReq_ReportCredentialsJudgement:
	case VMMDevReq_RegisterSharedModule:
	case VMMDevReq_UnregisterSharedModule:
	case VMMDevReq_WriteCoreDump:
	case VMMDevReq_GetCpuHotPlugRequest:
	case VMMDevReq_SetCpuHotPlugStatus:
	case VMMDevReq_CheckSharedModules:
	case VMMDevReq_GetPageSharingStatus:
	case VMMDevReq_DebugIsPageShared:
	case VMMDevReq_ReportGuestStats:
	case VMMDevReq_ReportGuestUserState:
	case VMMDevReq_GetStatisticsChangeRequest:
		trusted_apps_only = true;
		break;

	/* Anyone. */
	case VMMDevReq_GetMouseStatus:
	case VMMDevReq_SetMouseStatus:
	case VMMDevReq_SetPointerShape:
	case VMMDevReq_GetHostVersion:
	case VMMDevReq_Idle:
	case VMMDevReq_GetHostTime:
	case VMMDevReq_SetPowerStatus:
	case VMMDevReq_AcknowledgeEvents:
	case VMMDevReq_CtlGuestFilterMask:
	case VMMDevReq_ReportGuestStatus:
	case VMMDevReq_GetDisplayChangeRequest:
	case VMMDevReq_VideoModeSupported:
	case VMMDevReq_GetHeightReduction:
	case VMMDevReq_GetDisplayChangeRequest2:
	case VMMDevReq_VideoModeSupported2:
	case VMMDevReq_VideoAccelEnable:
	case VMMDevReq_VideoAccelFlush:
	case VMMDevReq_VideoSetVisibleRegion:
	case VMMDevReq_GetDisplayChangeRequestEx:
	case VMMDevReq_GetSeamlessChangeRequest:
	case VMMDevReq_GetVRDPChangeRequest:
	case VMMDevReq_LogString:
	case VMMDevReq_GetSessionId:
		trusted_apps_only = false;
		break;

	/**
	 * @todo this have to be changed into an I/O control and the facilities
	 *    tracked in the session so they can automatically be failed when
	 *    the session terminates without reporting the new status.
	 *
	 * The information presented by IGuest is not reliable without this!
	 */
	/* Depends on the request parameters... */
	case VMMDevReq_ReportGuestCapabilities:
		guest_status = (const struct vmmdev_guest_status *)req;
		switch (guest_status->facility) {
		case VBoxGuestFacilityType_All:
		case VBoxGuestFacilityType_VBoxGuestDriver:
			vbg_err("Denying userspace vmm report guest cap. call facility %#08x\n",
				guest_status->facility);
			return -EPERM;
		case VBoxGuestFacilityType_VBoxService:
			trusted_apps_only = true;
			break;
		case VBoxGuestFacilityType_VBoxTrayClient:
		case VBoxGuestFacilityType_Seamless:
		case VBoxGuestFacilityType_Graphics:
		default:
			trusted_apps_only = false;
			break;
		}
		break;

	/* Anything else is not allowed. */
	default:
		vbg_err("Denying userspace vmm call type %#08x\n",
			req->requestType);
		return -EPERM;
	}

	if (trusted_apps_only && session->user_session) {
		vbg_err("Denying userspace vmm call type %#08x through vboxuser device node\n",
			req->requestType);
		return -EPERM;
	}

	return 0;
}

static int vbg_ioctl_vmmrequest(struct vbg_dev *gdev,
				struct vbg_session *session, void *data)
{
	VBGLREQHDR *hdr = data;
	int ret;

	if (hdr->cbIn != hdr->cbOut)
		return -EINVAL;

	if (hdr->cbIn > VMMDEV_MAX_VMMDEVREQ_SIZE)
		return -E2BIG;

	if (hdr->uType == VBGLREQHDR_TYPE_DEFAULT)
		return -EINVAL;

	ret = vbg_req_allowed(gdev, session, data);
	if (ret < 0)
		return ret;

	vbg_req_perform(gdev, data);
	WARN_ON(hdr->rc == VINF_HGCM_ASYNC_EXECUTE);

	return 0;
}

static int vbg_ioctl_hgcm_connect(struct vbg_dev *gdev,
				  struct vbg_session *session,
				  VBGLIOCHGCMCONNECT *conn)
{
	unsigned long flags;
	u32 client_id;
	int i, ret;

	if (vbg_ioctl_chk(&conn->Hdr, sizeof(conn->u.In), sizeof(conn->u.Out)))
		return -EINVAL;

	/* Find a free place in the sessions clients array and claim it */
	spin_lock_irqsave(&gdev->session_spinlock, flags);
	for (i = 0; i < ARRAY_SIZE(session->hgcm_client_ids); i++) {
		if (!session->hgcm_client_ids[i]) {
			session->hgcm_client_ids[i] = U32_MAX;
			break;
		}
	}
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	if (i >= ARRAY_SIZE(session->hgcm_client_ids))
		return -EMFILE;

	ret = vbg_hgcm_connect(gdev, &conn->u.In.Loc, &client_id,
			       &conn->Hdr.rc);

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	if (ret == 0 && conn->Hdr.rc >= 0) {
		conn->u.Out.idClient = client_id;
		session->hgcm_client_ids[i] = client_id;
	} else {
		conn->u.Out.idClient = 0;
		session->hgcm_client_ids[i] = 0;
	}
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	return ret;
}

static int vbg_ioctl_hgcm_disconnect(struct vbg_dev *gdev,
				     struct vbg_session *session,
				     VBGLIOCHGCMDISCONNECT *disconn)
{
	unsigned long flags;
	u32 client_id;
	int i, ret;

	if (vbg_ioctl_chk(&disconn->Hdr, sizeof(disconn->u.In), 0))
		return -EINVAL;

	client_id = disconn->u.In.idClient;
	if (client_id == 0 || client_id == U32_MAX)
		return -EINVAL;

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	for (i = 0; i < ARRAY_SIZE(session->hgcm_client_ids); i++) {
		if (session->hgcm_client_ids[i] == client_id) {
			session->hgcm_client_ids[i] = U32_MAX;
			break;
		}
	}
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	if (i >= ARRAY_SIZE(session->hgcm_client_ids))
		return -EINVAL;

	ret = vbg_hgcm_disconnect(gdev, client_id, &disconn->Hdr.rc);

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	if (ret == 0 && disconn->Hdr.rc >= 0)
		session->hgcm_client_ids[i] = 0;
	else
		session->hgcm_client_ids[i] = client_id;
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	return ret;
}

static int vbg_ioctl_hgcm_call(struct vbg_dev *gdev,
			       struct vbg_session *session, bool f32bit,
			       VBGLIOCHGCMCALL *info)
{
	unsigned long flags;
	size_t actual_size;
	u32 client_id;
	int i, ret;

	if (info->Hdr.cbIn < sizeof(PVBGLIOCHGCMCALL))
		return -EINVAL;

	if (info->Hdr.cbIn != info->Hdr.cbOut)
		return -EINVAL;

	if (info->cParms > VBOX_HGCM_MAX_PARMS)
		return -E2BIG;

	client_id = info->u32ClientID;
	if (client_id == 0 || client_id == U32_MAX)
		return -EINVAL;

	actual_size = sizeof(*info);
	if (f32bit)
		actual_size += info->cParms *
			       sizeof(struct hgcm_function_parameter32);
	else
		actual_size += info->cParms *
			       sizeof(struct hgcm_function_parameter);
	if (info->Hdr.cbIn < actual_size) {
		vbg_debug("VBGL_IOCTL_HGCM_CALL: Hdr.cbIn %d required size is %zd\n",
			  info->Hdr.cbIn, actual_size);
		return -EINVAL;
	}
	info->Hdr.cbOut = actual_size;

	/*
	 * Validate the client id.
	 */
	spin_lock_irqsave(&gdev->session_spinlock, flags);
	for (i = 0; i < ARRAY_SIZE(session->hgcm_client_ids); i++)
		if (session->hgcm_client_ids[i] == client_id)
			break;
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);
	if (i >= ARRAY_SIZE(session->hgcm_client_ids)) {
		vbg_debug("VBGL_IOCTL_HGCM_CALL: Invalid handle. u32Client=%#08x\n",
			  client_id);
		return -EINVAL;
	}

	if (f32bit)
		ret = vbg_hgcm_call32(gdev, info);
	else
		ret = vbg_hgcm_call(gdev, info, true);

	if (ret == -E2BIG) {
		/* E2BIG needs to be reported through the Hdr.rc field. */
		info->Hdr.rc = VERR_OUT_OF_RANGE;
		ret = 0;
	}

	if (ret && ret != -EINTR && ret != -ETIMEDOUT)
		vbg_err("VBGL_IOCTL_HGCM_CALL error: %d\n", ret);

	return ret;
}

static int vbg_ioctl_log(VBGLIOCLOG *log)
{
	if (log->Hdr.cbOut != sizeof(log->Hdr))
		return -EINVAL;

	vbg_info("%.*s", (int)(log->Hdr.cbIn - sizeof(log->Hdr)),
		 log->u.In.szMsg);

	return 0;
}

/**
 * Handle VBGL_IOCTL_CHANGE_FILTER_MASK.
 *
 * @returns VBox status code
 * @param   gdev	The Guest extension device.
 * @param   session	The session.
 * @param   info	The request.
 */
static int vbg_ioctl_change_filter_mask(struct vbg_dev *gdev,
					struct vbg_session *session,
					VBGLIOCCHANGEFILTERMASK *filter)
{
	u32 or_mask, not_mask;

	if (vbg_ioctl_chk(&filter->Hdr, sizeof(filter->u.In), 0))
		return -EINVAL;

	or_mask = filter->u.In.fOrMask;
	not_mask = filter->u.In.fNotMask;

	if ((or_mask | not_mask) & ~VMMDEV_EVENT_VALID_EVENT_MASK)
		return -EINVAL;

	return vbg_set_session_event_filter(gdev, session, or_mask, not_mask,
					    false);
}

/**
 * Handle VBGL_IOCTL_CHANGE_GUEST_CAPABILITIES.
 *
 * @returns VBox status code
 * @param   gdev	The Guest extension device.
 * @param   session	The session.
 * @param   info	The request.
 */
static int vbg_ioctl_change_guest_capabilities(struct vbg_dev *gdev,
					       struct vbg_session *session,
					       VBGLIOCSETGUESTCAPS *caps)
{
	u32 or_mask, not_mask;
	int ret;

	if (vbg_ioctl_chk(&caps->Hdr, sizeof(caps->u.In), sizeof(caps->u.Out)))
		return -EINVAL;

	or_mask = caps->u.In.fOrMask;
	not_mask = caps->u.In.fNotMask;

	if ((or_mask | not_mask) & ~VMMDEV_EVENT_VALID_EVENT_MASK)
		return -EINVAL;

	ret = vbg_set_session_capabilities(gdev, session, or_mask, not_mask,
					   false);
	if (ret)
		return ret;

	caps->u.Out.fSessionCaps = session->guest_caps;
	caps->u.Out.fGlobalCaps = gdev->guest_caps_host;

	return 0;
}

static int vbg_ioctl_check_balloon(struct vbg_dev *gdev,
				   VBGLIOCCHECKBALLOON *balloon_info)
{
	if (vbg_ioctl_chk(&balloon_info->Hdr, 0, sizeof(balloon_info->u.Out)))
		return -EINVAL;

	balloon_info->u.Out.cBalloonChunks = gdev->mem_balloon.chunks;
	/*
	 * Under Linux we handle VMMDEV_EVENT_BALLOON_CHANGE_REQUEST
	 * events entirely in the kernel, see vbg_core_isr().
	 */
	balloon_info->u.Out.fHandleInR3 = false;

	return 0;
}

/**
 * Handle a request for writing a core dump of the guest on the host.
 *
 * @returns 0 or negative errno value.
 *
 * @param   gdev	The Guest extension device.
 * @param   dump	The i/o buffer.
 */
static int vbg_ioctl_write_core_dump(struct vbg_dev *gdev,
				     VBGLIOCWRITECOREDUMP *dump)
{
	struct vmmdev_write_core_dump *req;

	if (vbg_ioctl_chk(&dump->Hdr, sizeof(dump->u.In), 0))
		return -EINVAL;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_WriteCoreDump);
	if (!req)
		return -ENOMEM;

	req->fFlags = dump->u.In.fFlags;
	dump->Hdr.rc = vbg_req_perform(gdev, req);

	kfree(req);
	return 0;
}

/**
 * Common IOCtl for user to kernel communication.
 *
 * This function only does the basic validation and then invokes
 * worker functions that takes care of each specific function.
 *
 * @returns VBox status code
 * @param   session        The client session.
 * @param   req            The requested function.
 * @param   data           The i/o data buffer (minimum size VBGLREQHDR)
 */
int vbg_core_ioctl(struct vbg_session *session, unsigned int req, void *data)
{
	unsigned int req_no_size = req & ~IOCSIZE_MASK;
	struct vbg_dev *gdev = session->gdev;
	VBGLREQHDR *hdr = data;
	bool f32bit = false;

	hdr->rc = VINF_SUCCESS;
	if (!hdr->cbOut)
		hdr->cbOut = hdr->cbIn;

	/*
	 * hdr->uVersion and hdr->cbIn / hdr->cbOut minimum size are
	 * already checked by vbg_misc_device_ioctl().
	 */

	/* This is the only ioctl where hdr->uType != VBGLREQHDR_TYPE_DEFAULT */
	if (req_no_size == VBGL_IOCTL_VMMDEV_REQUEST(0) ||
	    req == VBGL_IOCTL_VMMDEV_REQUEST_BIG)
		return vbg_ioctl_vmmrequest(gdev, session, data);

	if (hdr->uType != VBGLREQHDR_TYPE_DEFAULT)
		return -EINVAL;

	/* Fixed size requests. */
	switch (req) {
	case VBGL_IOCTL_DRIVER_VERSION_INFO:
		return vbg_ioctl_driver_version_info(data);
	case VBGL_IOCTL_HGCM_CONNECT:
		return vbg_ioctl_hgcm_connect(gdev, session, data);
	case VBGL_IOCTL_HGCM_DISCONNECT:
		return vbg_ioctl_hgcm_disconnect(gdev, session, data);
	case VBGL_IOCTL_WAIT_FOR_EVENTS:
		return vbg_ioctl_wait_for_events(gdev, session, data);
	case VBGL_IOCTL_INTERRUPT_ALL_WAIT_FOR_EVENTS:
		return vbg_ioctl_interrupt_all_wait_events(gdev, session, data);
	case VBGL_IOCTL_CHANGE_FILTER_MASK:
		return vbg_ioctl_change_filter_mask(gdev, session, data);
	case VBGL_IOCTL_CHANGE_GUEST_CAPABILITIES:
		return vbg_ioctl_change_guest_capabilities(gdev, session, data);
	case VBGL_IOCTL_CHECK_BALLOON:
		return vbg_ioctl_check_balloon(gdev, data);
	case VBGL_IOCTL_WRITE_CORE_DUMP:
		return vbg_ioctl_write_core_dump(gdev, data);
	}

	/* Variable sized requests. */
	switch (req_no_size) {
#ifdef CONFIG_X86_64
	case VBGL_IOCTL_HGCM_CALL_32(0):
		f32bit = true;
		/* Fall through */
#endif
	case VBGL_IOCTL_HGCM_CALL(0):
		return vbg_ioctl_hgcm_call(gdev, session, f32bit, data);
	case VBGL_IOCTL_LOG(0):
		return vbg_ioctl_log(data);
	}

	vbg_debug("VGDrvCommonIoCtl: Unknown req %#08x\n", req);
	return -ENOTTY;
}

/**
 * Report guest supported mouse-features to the host.
 *
 * @returns 0 or negative errno value.
 * @returns VBox status code
 * @param   gdev	The Guest extension device.
 * @param   features	The set of features to report to the host.
 */
int vbg_core_set_mouse_status(struct vbg_dev *gdev, u32 features)
{
	struct vmmdev_mouse_status *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_SetMouseStatus);
	if (!req)
		return -ENOMEM;

	req->mouseFeatures = features;
	req->pointerXPos = 0;
	req->pointerYPos = 0;

	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		vbg_err("%s error, rc: %d\n", __func__, rc);

	kfree(req);
	return vbg_status_code_to_errno(rc);
}

/** Core interrupt service routine. */
irqreturn_t vbg_core_isr(int irq, void *dev_id)
{
	struct vbg_dev *gdev = dev_id;
	struct vmmdev_events *req = gdev->ack_events_req;
	bool mouse_position_changed = false;
	unsigned long flags;
	u32 events = 0;
	int rc;

	if (!gdev->mmio->V.V1_04.fHaveEvents)
		return IRQ_NONE;

	/* Get and acknowlegde events. */
	req->header.rc = VERR_INTERNAL_ERROR;
	req->events = 0;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0) {
		vbg_err("Error performing events req, rc: %d\n", rc);
		return IRQ_NONE;
	}

	events = req->events;

	if (events & VMMDEV_EVENT_MOUSE_POSITION_CHANGED) {
		mouse_position_changed = true;
		events &= ~VMMDEV_EVENT_MOUSE_POSITION_CHANGED;
	}

	if (events & VMMDEV_EVENT_HGCM) {
		wake_up(&gdev->hgcm_wq);
		events &= ~VMMDEV_EVENT_HGCM;
	}

	if (events & VMMDEV_EVENT_BALLOON_CHANGE_REQUEST) {
		schedule_work(&gdev->mem_balloon.work);
		events &= ~VMMDEV_EVENT_BALLOON_CHANGE_REQUEST;
	}

	if (events) {
		spin_lock_irqsave(&gdev->event_spinlock, flags);
		gdev->pending_events |= events;
		spin_unlock_irqrestore(&gdev->event_spinlock, flags);

		wake_up(&gdev->event_wq);
	}

	if (mouse_position_changed)
		vbg_linux_mouse_event(gdev);

	return IRQ_HANDLED;
}
