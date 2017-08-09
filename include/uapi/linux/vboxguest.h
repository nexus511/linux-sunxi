/*
 * VBoxGuest - VirtualBox Guest Additions Driver Interface.
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

#ifndef __UAPI_VBOXGUEST_H__
#define __UAPI_VBOXGUEST_H__

#include <asm/bitsperlong.h>
#include <linux/ioctl.h>
#include <linux/vbox_err.h>
#include <linux/vbox_vmmdev_types.h>

/* Version of VMMDevRequestHeader structure. */
#define VBGLREQHDR_VERSION		0x10001
/* Default request type.  Use this for non-VMMDev requests. */
#define VBGLREQHDR_TYPE_DEFAULT		0

/**
 * Common ioctl header.
 *
 * This is a mirror of vmmdev_request_header to prevent duplicating data and
 * needing to verify things multiple times.
 */
typedef struct VBGLREQHDR {
	/** IN: The request input size, and output size if cbOut is zero. */
	__u32 cbIn;
	/** IN: Structure version (VBGLREQHDR_VERSION) */
	__u32 uVersion;
	/** IN: The VMMDev request type or VBGLREQHDR_TYPE_DEFAULT. */
	__u32 uType;
	/**
	 * OUT: The VBox status code of the operation, out direction only.
	 * This is a VINF_ or VERR_ value as defined in vbox_err.h.
	 */
	__s32 rc;
	/** IN: Output size. Set to zero to use cbIn as output size. */
	__u32 cbOut;
	/** Reserved, MBZ. */
	__u32 uReserved;
} VBGLREQHDR, *PVBGLREQHDR;
VMMDEV_ASSERT_SIZE(VBGLREQHDR, 24);


/*
 * The VBoxGuest I/O control version.
 *
 * As usual, the high word contains the major version and changes to it
 * signifies incompatible changes.
 *
 * The lower word is the minor version number, it is increased when new
 * functions are added or existing changed in a backwards compatible manner.
 */
#define VBGL_IOC_VERSION		0x00010000u

/**
 * VBGL_IOCTL_DRIVER_VERSION_INFO data structure
 *
 * Note VBGL_IOCTL_DRIVER_VERSION_INFO may switch the session to a backwards
 * compatible interface version if uClientVersion indicates older client code.
 */
typedef struct VBGLIOCDRIVERVERSIONINFO {
	/** The header. */
	VBGLREQHDR Hdr;
	union {
		struct {
			/** Requested interface version (VBGL_IOC_VERSION). */
			__u32 uReqVersion;
			/**
			 * Minimum interface version number (typically the
			 * major version part of VBGL_IOC_VERSION).
			 */
			__u32 uMinVersion;
			/** Reserved, MBZ. */
			__u32 uReserved1;
			/** Reserved, MBZ. */
			__u32 uReserved2;
		} In;
		struct {
			/** Version for this session (typ. VBGL_IOC_VERSION). */
			__u32 uSessionVersion;
			/** Version of the IDC interface (VBGL_IOC_VERSION). */
			__u32 uDriverVersion;
			/** The SVN revision of the driver, or 0. */
			__u32 uDriverRevision;
			/** Reserved \#1 (zero until defined). */
			__u32 uReserved1;
			/** Reserved \#2 (zero until defined). */
			__u32 uReserved2;
		} Out;
	} u;
} VBGLIOCDRIVERVERSIONINFO, *PVBGLIOCDRIVERVERSIONINFO;
VMMDEV_ASSERT_SIZE(VBGLIOCDRIVERVERSIONINFO, 24 + 20);

#define VBGL_IOCTL_DRIVER_VERSION_INFO	_IOWR('V', 0, VBGLIOCDRIVERVERSIONINFO)


/* IOCTL to perform a VMM Device request less than 1KB in size. */
#define VBGL_IOCTL_VMMDEV_REQUEST(s)	_IOC(_IOC_READ | _IOC_WRITE, 'V', 2, s)


/* IOCTL to perform a VMM Device request larger then 1KB. */
#define VBGL_IOCTL_VMMDEV_REQUEST_BIG	_IOC(_IOC_READ | _IOC_WRITE, 'V', 3, 0)


/** VBGL_IOCTL_HGCM_CONNECT data structure. */
typedef struct VBGLIOCHGCMCONNECT {
	VBGLREQHDR Hdr;
	union {
		struct {
			struct hgcm_service_location Loc;
		} In;
		struct {
			__u32 idClient;
		} Out;
	} u;
} VBGLIOCHGCMCONNECT, *PVBGLIOCHGCMCONNECT;
VMMDEV_ASSERT_SIZE(VBGLIOCHGCMCONNECT, 24 + 132);

#define VBGL_IOCTL_HGCM_CONNECT		_IOWR('V', 4, VBGLIOCHGCMCONNECT)


/** VBGL_IOCTL_HGCM_DISCONNECT data structure. */
typedef struct VBGLIOCHGCMDISCONNECT {
	VBGLREQHDR Hdr;
	union {
		struct {
			__u32 idClient;
		} In;
	} u;
} VBGLIOCHGCMDISCONNECT, *PVBGLIOCHGCMDISCONNECT;
VMMDEV_ASSERT_SIZE(VBGLIOCHGCMDISCONNECT, 24 + 4);

#define VBGL_IOCTL_HGCM_DISCONNECT	_IOWR('V', 5, VBGLIOCHGCMDISCONNECT)


/** VBGL_IOCTL_HGCM_CALL data structure. */
typedef struct VBGLIOCHGCMCALL {
	/** The header. */
	VBGLREQHDR Hdr;
	/** Input: The id of the caller. */
	__u32 u32ClientID;
	/** Input: Function number. */
	__u32 u32Function;
	/**
	 * Input: How long to wait (milliseconds) for completion before
	 * cancelling the call. Set to -1 to wait indefinitely.
	 */
	__u32 cMsTimeout;
	/** Interruptable flag, ignored for userspace calls. */
	__u8 fInterruptible;
	/** Explicit padding, MBZ. */
	__u8 bReserved;
	/**
	 * Input: How many parameters following this structure.
	 *
	 * The parameters are either HGCMFunctionParameter64 or 32,
	 * depending on whether we're receiving a 64-bit or 32-bit request.
	 *
	 * The current maximum is 61 parameters (given a 1KB max request size,
	 * and a 64-bit parameter size of 16 bytes).
	 */
	__u16 cParms;
	/* Parameters follow in form HGCMFunctionParameter aParms[cParms] */
} VBGLIOCHGCMCALL, *PVBGLIOCHGCMCALL;
VMMDEV_ASSERT_SIZE(VBGLIOCHGCMCALL, 24 + 16);

#define VBGL_IOCTL_HGCM_CALL_32(s)	_IOC(_IOC_READ | _IOC_WRITE, 'V', 6, s)
#define VBGL_IOCTL_HGCM_CALL_64(s)	_IOC(_IOC_READ | _IOC_WRITE, 'V', 7, s)
#if __BITS_PER_LONG == 64
#define VBGL_IOCTL_HGCM_CALL(s)		VBGL_IOCTL_HGCM_CALL_64(s)
#else
#define VBGL_IOCTL_HGCM_CALL(s)		VBGL_IOCTL_HGCM_CALL_32(s)
#endif


/** VBGL_IOCTL_LOG data structure. */
typedef struct VBGLIOCLOG {
	/** The header. */
	VBGLREQHDR Hdr;
	union {
		struct {
			/**
			 * The log message, this may be zero terminated. If it
			 * is not zero terminated then the length is determined
			 * from the input size.
			 */
			char szMsg[1];
		} In;
	} u;
} VBGLIOCLOG, *PVBGLIOCLOG;

#define VBGL_IOCTL_LOG(s)		_IOC(_IOC_READ | _IOC_WRITE, 'V', 9, s)


/** VBGL_IOCTL_WAIT_FOR_EVENTS data structure. */
typedef struct VBGLIOCWAITFOREVENTS {
	/** The header. */
	VBGLREQHDR Hdr;
	union {
		struct {
			/** Timeout in milliseconds. */
			__u32 cMsTimeOut;
			/** Events to wait for. */
			__u32 fEvents;
		} In;
		struct {
			/** Events that occurred. */
			__u32 fEvents;
		} Out;
	} u;
} VBGLIOCWAITFOREVENTS, *PVBGLIOCWAITFOREVENTS;
VMMDEV_ASSERT_SIZE(VBGLIOCWAITFOREVENTS, 24 + 8);

#define VBGL_IOCTL_WAIT_FOR_EVENTS	_IOWR('V', 10, VBGLIOCWAITFOREVENTS)


/*
 * IOCTL to VBoxGuest to interrupt (cancel) any pending
 * VBGL_IOCTL_WAIT_FOR_EVENTS and return.
 *
 * Handled inside the vboxguest driver and not seen by the host at all.
 * After calling this, VBGL_IOCTL_WAIT_FOR_EVENTS should no longer be called in
 * the same session. Any VBOXGUEST_IOCTL_WAITEVENT calls in the same session
 * done after calling this will directly exit with -EINTR.
 */
#define VBGL_IOCTL_INTERRUPT_ALL_WAIT_FOR_EVENTS   _IOWR('V', 11, VBGLREQHDR)


/** VBGL_IOCTL_CHANGE_FILTER_MASK data structure. */
typedef struct VBGLIOCCHANGEFILTERMASK {
	/** The header. */
	VBGLREQHDR Hdr;
	union {
		struct {
			/** Flags to set. */
			__u32 fOrMask;
			/** Flags to remove. */
			__u32 fNotMask;
		} In;
	} u;
} VBGLIOCCHANGEFILTERMASK, *PVBGLIOCCHANGEFILTERMASK;
VMMDEV_ASSERT_SIZE(VBGLIOCCHANGEFILTERMASK, 24 + 8);

/* IOCTL to VBoxGuest to control the event filter mask. */
#define VBGL_IOCTL_CHANGE_FILTER_MASK	_IOWR('V', 12, VBGLIOCCHANGEFILTERMASK)


/** VBGL_IOCTL_CHANGE_GUEST_CAPABILITIES data structure. */
typedef struct VBGLIOCSETGUESTCAPS {
	/** The header. */
	VBGLREQHDR Hdr;
	union {
		struct {
			/** Capabilities to set (VMMDEV_GUEST_SUPPORTS_XXX). */
			__u32 fOrMask;
			/** Capabilities to drop (VMMDEV_GUEST_SUPPORTS_XXX). */
			__u32 fNotMask;
		} In;
		struct {
			/** Capabilities held by the session after the call. */
			__u32 fSessionCaps;
			/** Capabilities for all the sessions after the call. */
			__u32 fGlobalCaps;
		} Out;
	} u;
} VBGLIOCSETGUESTCAPS, *PVBGLIOCSETGUESTCAPS;
VMMDEV_ASSERT_SIZE(VBGLIOCSETGUESTCAPS, 24 + 8);

#define VBGL_IOCTL_CHANGE_GUEST_CAPABILITIES _IOWR('V', 14, VBGLIOCSETGUESTCAPS)


/** VBGL_IOCTL_CHECK_BALLOON data structure. */
typedef struct VBGLIOCCHECKBALLOON {
	/** The header. */
	VBGLREQHDR Hdr;
	union {
		struct {
			/** The size of the balloon in chunks of 1MB. */
			__u32 cBalloonChunks;
			/**
			 * false = handled in R0, no further action required.
			 *  true = allocate balloon memory in R3.
			 */
			__u8 fHandleInR3;
			/** Explicit padding, please ignore. */
			__u8 afPadding[3];
		} Out;
	} u;
} VBGLIOCCHECKBALLOON, *PVBGLIOCCHECKBALLOON;
VMMDEV_ASSERT_SIZE(VBGLIOCCHECKBALLOON, 24 + 8);

/*
 * IOCTL to check memory ballooning.
 *
 * The guest kernel module will ask the host for the current size of the
 * balloon and adjust the size. Or it will set fHandleInR3 = true and R3 is
 * responsible for allocating memory and calling VBGL_IOCTL_CHANGE_BALLOON.
 */
#define VBGL_IOCTL_CHECK_BALLOON	_IOWR('V', 17, VBGLIOCCHECKBALLOON)


/** VBGL_IOCTL_WRITE_CORE_DUMP data structure. */
typedef struct VBGLIOCWRITECOREDUMP {
	VBGLREQHDR Hdr;
	union {
		struct {
			__u32 fFlags; /** Flags (reserved, MBZ). */
		} In;
	} u;
} VBGLIOCWRITECOREDUMP, *PVBGLIOCWRITECOREDUMP;
VMMDEV_ASSERT_SIZE(VBGLIOCWRITECOREDUMP, 24 + 4);

#define VBGL_IOCTL_WRITE_CORE_DUMP	_IOWR('V', 19, VBGLIOCWRITECOREDUMP)

#endif
