/*
 * Copyright (C) 2006-2016 Oracle Corporation
 *
 * Wrapper functions for the shfl host calls.
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

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vbox_err.h>
#include <linux/vbox_utils.h>
#include "vboxsf_wrappers.h"

#undef READ
#undef WRITE

#define VBOX_INIT_CALLINFO(c, size, func)				\
do {									\
	(c)->Hdr.cbIn       = size;					\
	(c)->Hdr.uVersion   = VBGLREQHDR_VERSION;			\
	(c)->Hdr.uType      = VBGLREQHDR_TYPE_DEFAULT;			\
	(c)->Hdr.rc         = VERR_INTERNAL_ERROR;			\
	(c)->Hdr.cbOut      = size;					\
	(c)->Hdr.uReserved  = 0;					\
	(c)->u32ClientID    = vboxsf_client_id;				\
	(c)->u32Function    = SHFL_FN_##func;     			\
	(c)->cMsTimeout     = U32_MAX;					\
	(c)->fInterruptible = false;					\
	(c)->bReserved      = 0;					\
	(c)->cParms         = SHFL_CPARMS_##func; 			\
} while (0)

#define VBOX_INIT_CALL(c, func)						\
	VBOX_INIT_CALLINFO(&((c)->call_info), sizeof(*(c)), func)

/* globals */
static u32 vboxsf_client_id;

int vboxsf_connect(void)
{
	struct vbg_dev *gdev;
	struct hgcm_service_location loc;
	int err, rc;

	loc.type = VMMDevHGCMLoc_LocalHost_Existing;
	strcpy(loc.u.host.achName, "VBoxSharedFolders");

	gdev = vbg_get_gdev();
	if (IS_ERR(gdev))
		return VERR_NOT_SUPPORTED;	/* No guest-device */

	err = vbg_hgcm_connect(gdev, &loc, &vboxsf_client_id, &rc);
	vbg_put_gdev(gdev);

	return err ? err : vbg_status_code_to_errno(rc);
}

void vboxsf_disconnect(void)
{
	struct vbg_dev *gdev;
	int rc;

	gdev = vbg_get_gdev();
	if (IS_ERR(gdev))
		return;   /* guest-device is gone, already disconnected */

	vbg_hgcm_disconnect(gdev, vboxsf_client_id, &rc);
	vbg_put_gdev(gdev);
}

static int vboxsf_hgcm_call(void *data)
{
	VBGLIOCHGCMCALL *info = data;
	struct vbg_dev *gdev;
	int ret;

	gdev = vbg_get_gdev();
	if (IS_ERR(gdev))
		return VERR_DEV_IO_ERROR; /* guest-dev removed underneath us */

	ret = vbg_hgcm_call(gdev, info, false);
	vbg_put_gdev(gdev);

	if (ret < 0)
		return ret == -ENOMEM ? VERR_NO_MEMORY : VERR_DEV_IO_ERROR;

	return info->Hdr.rc;
}

int vboxsf_query_mappings(struct shfl_mapping mappings[], u32 *mappings_len)
{
	int rc;
	struct shfl_query_mappings data;

	VBOX_INIT_CALL(&data, QUERY_MAPPINGS);

	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = SHFL_MF_UCS2;

	data.number_of_mappings.type = VMMDevHGCMParmType_32bit;
	data.number_of_mappings.u.value32 = *mappings_len;

	data.mappings.type = VMMDevHGCMParmType_LinAddr;
	data.mappings.u.Pointer.size = sizeof(struct shfl_mapping) *
				       *mappings_len;
	data.mappings.u.Pointer.u.linearAddr = (uintptr_t)&mappings[0];

	rc = vboxsf_hgcm_call(&data);
	if (rc >= 0)
		*mappings_len = data.number_of_mappings.u.value32;

	return rc;
}

int vboxsf_query_mapname(SHFLROOT root, struct shfl_string *string, u32 size)
{
	struct shfl_query_map_name data;

	VBOX_INIT_CALL(&data, QUERY_MAP_NAME);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.name.type = VMMDevHGCMParmType_LinAddr;
	data.name.u.Pointer.size = size;
	data.name.u.Pointer.u.linearAddr = (uintptr_t)string;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_map_folder(struct shfl_string *folder_name, SHFLROOT *root)
{
	int rc;
	struct shfl_map_folder data;

	VBOX_INIT_CALL(&data, MAP_FOLDER);

	data.path.type = VMMDevHGCMParmType_LinAddr;
	data.path.u.Pointer.size = shfl_string_buf_size(folder_name);
	data.path.u.Pointer.u.linearAddr = (uintptr_t)folder_name;

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = 0;

	data.delimiter.type = VMMDevHGCMParmType_32bit;
	data.delimiter.u.value32 = '/';

	data.case_sensitive.type = VMMDevHGCMParmType_32bit;
	data.case_sensitive.u.value32 = 1;

	rc = vboxsf_hgcm_call(&data);
	if (rc >= 0)
		*root = data.root.u.value32;
	else if (rc == VERR_NOT_IMPLEMENTED)
		vbg_err("%s: Error host is too old\n", __func__);

	return rc;
}

int vboxsf_unmap_folder(SHFLROOT root)
{
	struct shfl_unmap_folder data;

	VBOX_INIT_CALL(&data, UNMAP_FOLDER);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_create(SHFLROOT root, struct shfl_string *parsed_path,
		  struct shfl_createparms *create_parms)
{
	/** @todo copy buffers to physical or mapped memory. */
	struct shfl_create data;

	VBOX_INIT_CALL(&data, CREATE);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.path.type = VMMDevHGCMParmType_LinAddr;
	data.path.u.Pointer.size = shfl_string_buf_size(parsed_path);
	data.path.u.Pointer.u.linearAddr = (uintptr_t)parsed_path;

	data.parms.type = VMMDevHGCMParmType_LinAddr;
	data.parms.u.Pointer.size = sizeof(struct shfl_createparms);
	data.parms.u.Pointer.u.linearAddr = (uintptr_t)create_parms;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_close(SHFLROOT root, SHFLHANDLE file)
{
	struct shfl_close data;

	VBOX_INIT_CALL(&data, CLOSE);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = file;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_remove(SHFLROOT root, struct shfl_string *parsed_path, u32 flags)
{
	struct shfl_remove data;

	VBOX_INIT_CALL(&data, REMOVE);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.path.type = VMMDevHGCMParmType_LinAddr_In;
	data.path.u.Pointer.size = shfl_string_buf_size(parsed_path);
	data.path.u.Pointer.u.linearAddr = (uintptr_t)parsed_path;

	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = flags;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_rename(SHFLROOT root, struct shfl_string *src_path,
		  struct shfl_string *dest_path, u32 flags)
{
	struct shfl_rename data;

	VBOX_INIT_CALL(&data, RENAME);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.src.type = VMMDevHGCMParmType_LinAddr_In;
	data.src.u.Pointer.size = shfl_string_buf_size(src_path);
	data.src.u.Pointer.u.linearAddr = (uintptr_t)src_path;

	data.dest.type = VMMDevHGCMParmType_LinAddr_In;
	data.dest.u.Pointer.size = shfl_string_buf_size(dest_path);
	data.dest.u.Pointer.u.linearAddr = (uintptr_t)dest_path;

	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = flags;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_read(SHFLROOT root, SHFLHANDLE file, u64 offset,
		u32 *buf_len, u8 *buf)
{
	int rc;
	struct shfl_read data;

	VBOX_INIT_CALL(&data, READ);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = file;
	data.offset.type = VMMDevHGCMParmType_64bit;
	data.offset.u.value64 = offset;
	data.cb.type = VMMDevHGCMParmType_32bit;
	data.cb.u.value32 = *buf_len;
	data.buffer.type = VMMDevHGCMParmType_LinAddr_Out;
	data.buffer.u.Pointer.size = *buf_len;
	data.buffer.u.Pointer.u.linearAddr = (uintptr_t)buf;

	rc = vboxsf_hgcm_call(&data);
	if (rc >= 0)
		*buf_len = data.cb.u.value32;

	return rc;
}

int vboxsf_write(SHFLROOT root, SHFLHANDLE file, u64 offset,
		 u32 *buf_len, u8 *buf)
{
	int rc;
	struct shfl_write data;

	VBOX_INIT_CALL(&data, WRITE);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = file;
	data.offset.type = VMMDevHGCMParmType_64bit;
	data.offset.u.value64 = offset;
	data.cb.type = VMMDevHGCMParmType_32bit;
	data.cb.u.value32 = *buf_len;
	data.buffer.type = VMMDevHGCMParmType_LinAddr_In;
	data.buffer.u.Pointer.size = *buf_len;
	data.buffer.u.Pointer.u.linearAddr = (uintptr_t)buf;

	rc = vboxsf_hgcm_call(&data);
	if (rc >= 0)
		*buf_len = data.cb.u.value32;

	return rc;
}

int vboxsf_write_physcont(SHFLROOT root, SHFLHANDLE file, u64 offset,
			  u32 *buf_len, u64 phys_buf)
{
	struct hgcm_pagelist *pg_lst;
	u32 i, pages, data_len;
	struct shfl_write *data;
	int rc;

	pages = PAGE_ALIGN((phys_buf & ~PAGE_MASK) + *buf_len) >> PAGE_SHIFT;
	data_len = sizeof(struct shfl_write) +
		   offsetof(struct hgcm_pagelist, aPages[pages]);

	data = kmalloc(data_len, GFP_KERNEL);
	if (!data)
		return VERR_NO_TMP_MEMORY;

	VBOX_INIT_CALLINFO(&data->call_info, data_len, WRITE);

	data->root.type = VMMDevHGCMParmType_32bit;
	data->root.u.value32 = root;

	data->handle.type = VMMDevHGCMParmType_64bit;
	data->handle.u.value64 = file;
	data->offset.type = VMMDevHGCMParmType_64bit;
	data->offset.u.value64 = offset;
	data->cb.type = VMMDevHGCMParmType_32bit;
	data->cb.u.value32 = *buf_len;
	data->buffer.type = VMMDevHGCMParmType_PageList;
	data->buffer.u.PageList.size = *buf_len;
	data->buffer.u.PageList.offset = sizeof(struct shfl_write);

	pg_lst = (struct hgcm_pagelist *)(data + 1);
	pg_lst->flags = VBOX_HGCM_F_PARM_DIRECTION_TO_HOST;
	pg_lst->offFirstPage = (u16)(phys_buf & ~PAGE_MASK);
	pg_lst->cPages = pages;
	phys_buf = ALIGN_DOWN(phys_buf, PAGE_SIZE);
	for (i = 0; i < pages; i++, phys_buf += PAGE_SIZE)
		pg_lst->aPages[i] = phys_buf;

	rc = vboxsf_hgcm_call(data);
	if (rc >= 0)
		*buf_len = data->cb.u.value32;

	kfree(data);
	return rc;
}

int vboxsf_flush(SHFLROOT root, SHFLHANDLE file)
{
	struct shfl_flush data;

	VBOX_INIT_CALL(&data, FLUSH);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = file;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_dirinfo(SHFLROOT root, SHFLHANDLE file,
		   struct shfl_string *parsed_path, u32 flags, u32 index,
		   u32 *buf_len, struct shfl_dirinfo *buf, u32 *file_count)
{
	int rc;
	struct shfl_list data;

	VBOX_INIT_CALL(&data, LIST);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = file;
	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = flags;
	data.cb.type = VMMDevHGCMParmType_32bit;
	data.cb.u.value32 = *buf_len;
	data.path.type = VMMDevHGCMParmType_LinAddr_In;
	data.path.u.Pointer.size =
	    parsed_path ? shfl_string_buf_size(parsed_path) : 0;
	data.path.u.Pointer.u.linearAddr = (uintptr_t)parsed_path;

	data.buffer.type = VMMDevHGCMParmType_LinAddr_Out;
	data.buffer.u.Pointer.size = *buf_len;
	data.buffer.u.Pointer.u.linearAddr = (uintptr_t)buf;

	data.resume_point.type = VMMDevHGCMParmType_32bit;
	data.resume_point.u.value32 = index;
	data.file_count.type = VMMDevHGCMParmType_32bit;
	data.file_count.u.value32 = 0;	/* out parameters only */

	rc = vboxsf_hgcm_call(&data);

	*buf_len = data.cb.u.value32;
	*file_count = data.file_count.u.value32;

	return rc;
}

int vboxsf_fsinfo(SHFLROOT root, SHFLHANDLE file, u32 flags,
		  u32 *buf_len, void *buf)
{
	int rc;
	struct shfl_information data;

	VBOX_INIT_CALL(&data, INFORMATION);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = file;
	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = flags;
	data.cb.type = VMMDevHGCMParmType_32bit;
	data.cb.u.value32 = *buf_len;
	data.info.type = VMMDevHGCMParmType_LinAddr;
	data.info.u.Pointer.size = *buf_len;
	data.info.u.Pointer.u.linearAddr = (uintptr_t)buf;

	rc = vboxsf_hgcm_call(&data);
	if (rc >= 0)
		*buf_len = data.cb.u.value32;

	return rc;
}

int vboxsf_lock(SHFLROOT root, SHFLHANDLE file, u64 offset,
		u64 size, u32 lock)
{
	struct shfl_lock data;

	VBOX_INIT_CALL(&data, LOCK);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = file;
	data.offset.type = VMMDevHGCMParmType_64bit;
	data.offset.u.value64 = offset;
	data.length.type = VMMDevHGCMParmType_64bit;
	data.length.u.value64 = size;

	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = lock;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_set_utf8(void)
{
	VBGLIOCHGCMCALL info;

	VBOX_INIT_CALLINFO(&info, sizeof(info), SET_UTF8);

	return vboxsf_hgcm_call(&info);
}

int vboxsf_readlink(SHFLROOT root, struct shfl_string *parsed_path,
		    u32 buf_len, u8 *buf)
{
	struct shfl_readLink data;

	VBOX_INIT_CALL(&data, READLINK);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.path.type = VMMDevHGCMParmType_LinAddr_In;
	data.path.u.Pointer.size = shfl_string_buf_size(parsed_path);
	data.path.u.Pointer.u.linearAddr = (uintptr_t)parsed_path;

	data.buffer.type = VMMDevHGCMParmType_LinAddr_Out;
	data.buffer.u.Pointer.size = buf_len;
	data.buffer.u.Pointer.u.linearAddr = (uintptr_t)buf;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_symlink(SHFLROOT root, struct shfl_string *new_path,
		   struct shfl_string *old_path, struct shfl_fsobjinfo *buf)
{
	struct shfl_symlink data;

	VBOX_INIT_CALL(&data, SYMLINK);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.new_path.type = VMMDevHGCMParmType_LinAddr_In;
	data.new_path.u.Pointer.size = shfl_string_buf_size(new_path);
	data.new_path.u.Pointer.u.linearAddr = (uintptr_t)new_path;

	data.old_path.type = VMMDevHGCMParmType_LinAddr_In;
	data.old_path.u.Pointer.size = shfl_string_buf_size(old_path);
	data.old_path.u.Pointer.u.linearAddr = (uintptr_t)old_path;

	data.info.type = VMMDevHGCMParmType_LinAddr_Out;
	data.info.u.Pointer.size = sizeof(struct shfl_fsobjinfo);
	data.info.u.Pointer.u.linearAddr = (uintptr_t)buf;

	return vboxsf_hgcm_call(&data);
}

int vboxsf_set_symlinks(void)
{
	VBGLIOCHGCMCALL info;

	VBOX_INIT_CALLINFO(&info, sizeof(info), SET_SYMLINKS);

	return vboxsf_hgcm_call(&info);
}
