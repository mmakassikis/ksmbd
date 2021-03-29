// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/version.h>
#include <linux/xattr.h>
#include <linux/falloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/fsnotify.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/crc32c.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/xacct.h>
#else
#include <linux/sched.h>
#endif

#include "glob.h"
#include "oplock.h"
#include "connection.h"
#include "buffer_pool.h"
#include "vfs.h"
#include "vfs_cache.h"
#include "smbacl.h"
#include "ndr.h"
#include "auth.h"

#include "time_wrappers.h"
#include "smb_common.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "mgmt/user_config.h"

static char *extract_last_component(char *path)
{
	char *p = strrchr(path, '/');

	if (p && p[1] != '\0') {
		*p = '\0';
		p++;
	} else {
		p = NULL;
		ksmbd_err("Invalid path %s\n", path);
	}
	return p;
}

static void rollback_path_modification(char *filename)
{
	if (filename) {
		filename--;
		*filename = '/';
	}
}

static void ksmbd_vfs_inherit_owner(struct ksmbd_work *work,
		struct inode *parent_inode, struct inode *inode)
{
	if (!test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_INHERIT_OWNER))
		return;

	i_uid_write(inode, i_uid_read(parent_inode));
}

static void ksmbd_vfs_inherit_smack(struct ksmbd_work *work,
		struct dentry *dir_dentry, struct dentry *dentry)
{
	char *name, *xattr_list = NULL, *smack_buf;
	int value_len, xattr_list_len;

	if (!test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_INHERIT_SMACK))
		return;

	xattr_list_len = ksmbd_vfs_listxattr(dir_dentry, &xattr_list);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		ksmbd_err("no ea data in the file\n");
		return;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		int rc;

		ksmbd_debug(VFS, "%s, len %zd\n", name, strlen(name));
		if (strcmp(name, XATTR_NAME_SMACK))
			continue;

		value_len = ksmbd_vfs_getxattr(dir_dentry, name, &smack_buf);
		if (value_len <= 0)
			continue;

		rc = ksmbd_vfs_setxattr(dentry, XATTR_NAME_SMACK, smack_buf,
					value_len, 0);
		ksmbd_free(smack_buf);
		if (rc < 0)
			ksmbd_err("ksmbd_vfs_setxattr() failed: %d\n", rc);
	}
out:
	ksmbd_vfs_xattr_free(xattr_list);
}

int ksmbd_vfs_inode_permission(struct dentry *dentry, int acc_mode, bool delete)
{
	int mask;

	mask = 0;
	acc_mode &= O_ACCMODE;

	if (acc_mode == O_RDONLY)
		mask = MAY_READ;
	else if (acc_mode == O_WRONLY)
		mask = MAY_WRITE;
	else if (acc_mode == O_RDWR)
		mask = MAY_READ | MAY_WRITE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	if (inode_permission(&init_user_ns, d_inode(dentry), mask | MAY_OPEN))
#else
	if (inode_permission(d_inode(dentry), mask | MAY_OPEN))
#endif
		return -EACCES;

	if (delete) {
		struct dentry *parent;

		parent = dget_parent(dentry);
		if (!parent)
			return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		if (inode_permission(&init_user_ns, d_inode(parent), MAY_EXEC | MAY_WRITE)) {
#else
		if (inode_permission(d_inode(parent), MAY_EXEC | MAY_WRITE)) {
#endif
			dput(parent);
			return -EACCES;
		}
		dput(parent);
	}
	return 0;
}

int ksmbd_vfs_query_maximal_access(struct dentry *dentry, __le32 *daccess)
{
	struct dentry *parent;

	*daccess = cpu_to_le32(FILE_READ_ATTRIBUTES | READ_CONTROL);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	if (!inode_permission(&init_user_ns, d_inode(dentry), MAY_OPEN | MAY_WRITE))
#else
	if (!inode_permission(d_inode(dentry), MAY_OPEN | MAY_WRITE))
#endif
		*daccess |= cpu_to_le32(WRITE_DAC | WRITE_OWNER | SYNCHRONIZE |
				FILE_WRITE_DATA | FILE_APPEND_DATA |
				FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
				FILE_DELETE_CHILD);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	if (!inode_permission(&init_user_ns, d_inode(dentry), MAY_OPEN | MAY_READ))
#else
	if (!inode_permission(d_inode(dentry), MAY_OPEN | MAY_READ))
#endif
		*daccess |= FILE_READ_DATA_LE | FILE_READ_EA_LE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	if (!inode_permission(&init_user_ns, d_inode(dentry), MAY_OPEN | MAY_EXEC))
#else
	if (!inode_permission(d_inode(dentry), MAY_OPEN | MAY_EXEC))
#endif
		*daccess |= FILE_EXECUTE_LE;

	parent = dget_parent(dentry);
	if (!parent)
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	if (!inode_permission(&init_user_ns, d_inode(parent), MAY_EXEC | MAY_WRITE))
#else
	if (!inode_permission(d_inode(parent), MAY_EXEC | MAY_WRITE))
#endif
		*daccess |= FILE_DELETE_LE;
	dput(parent);
	return 0;
}

/**
 * ksmbd_vfs_create() - vfs helper for smb create file
 * @work:	work
 * @name:	file name
 * @mode:	file create mode
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_create(struct ksmbd_work *work, const char *name, umode_t mode)
{
	struct path path;
	struct dentry *dentry;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, 0);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		if (err != -ENOENT)
			ksmbd_err("path create failed for %s, err %d\n",
				name, err);
		return err;
	}

	mode |= S_IFREG;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	err = vfs_create(&init_user_ns, d_inode(path.dentry), dentry, mode, true);
#else
	err = vfs_create(d_inode(path.dentry), dentry, mode, true);
#endif
	if (!err) {
		ksmbd_vfs_inherit_owner(work, d_inode(path.dentry),
			d_inode(dentry));
		ksmbd_vfs_inherit_smack(work, path.dentry, dentry);
	} else {
		ksmbd_err("File(%s): creation failed (err:%d)\n", name, err);
	}
	done_path_create(&path, dentry);
	return err;
}

/**
 * ksmbd_vfs_mkdir() - vfs helper for smb create directory
 * @work:	work
 * @name:	directory name
 * @mode:	directory create mode
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_mkdir(struct ksmbd_work *work, const char *name, umode_t mode)
{
	struct path path;
	struct dentry *dentry;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		if (err != -EEXIST)
			ksmbd_debug(VFS, "path create failed for %s, err %d\n",
					name, err);
		return err;
	}

	mode |= S_IFDIR;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	err = vfs_mkdir(&init_user_ns, d_inode(path.dentry), dentry, mode);
#else
	err = vfs_mkdir(d_inode(path.dentry), dentry, mode);
#endif
	if (!err) {
		ksmbd_vfs_inherit_owner(work, d_inode(path.dentry),
			d_inode(dentry));
		ksmbd_vfs_inherit_smack(work, path.dentry, dentry);
	} else {
		ksmbd_err("mkdir(%s): creation failed (err:%d)\n", name, err);
	}

	done_path_create(&path, dentry);
	return err;
}

static ssize_t ksmbd_vfs_getcasexattr(struct dentry *dentry, char *attr_name,
		int attr_name_len, char **attr_value)
{
	char *name, *xattr_list = NULL;
	ssize_t value_len = -ENOENT, xattr_list_len;

	xattr_list_len = ksmbd_vfs_listxattr(dentry, &xattr_list);
	if (xattr_list_len <= 0)
		goto out;

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		ksmbd_debug(VFS, "%s, len %zd\n", name, strlen(name));
		if (strncasecmp(attr_name, name, attr_name_len))
			continue;

		value_len = ksmbd_vfs_getxattr(dentry,
					       name,
					       attr_value);
		if (value_len < 0)
			ksmbd_err("failed to get xattr in file\n");
		break;
	}

out:
	ksmbd_vfs_xattr_free(xattr_list);
	return value_len;
}

static int ksmbd_vfs_stream_read(struct ksmbd_file *fp, char *buf, loff_t *pos,
		size_t count)
{
	ssize_t v_len;
	char *stream_buf = NULL;
	int err;

	ksmbd_debug(VFS, "read stream data pos : %llu, count : %zd\n",
			*pos, count);

	v_len = ksmbd_vfs_getcasexattr(fp->filp->f_path.dentry,
				       fp->stream.name,
				       fp->stream.size,
				       &stream_buf);
	if (v_len == -ENOENT) {
		ksmbd_err("not found stream in xattr : %zd\n", v_len);
		err = -ENOENT;
		return err;
	}

	memcpy(buf, &stream_buf[*pos], count);
	return v_len > count ? count : v_len;
}

/**
 * check_lock_range() - vfs helper for smb byte range file locking
 * @filp:	the file to apply the lock to
 * @start:	lock start byte offset
 * @end:	lock end byte offset
 * @type:	byte range type read/write
 *
 * Return:	0 on success, otherwise error
 */
static int check_lock_range(struct file *filp, loff_t start, loff_t end,
		unsigned char type)
{
	struct file_lock *flock;
	struct file_lock_context *ctx = file_inode(filp)->i_flctx;
	int error = 0;

	if (!ctx || list_empty_careful(&ctx->flc_posix))
		return 0;

	spin_lock(&ctx->flc_lock);
	list_for_each_entry(flock, &ctx->flc_posix, fl_list) {
		/* check conflict locks */
		if (flock->fl_end >= start && end >= flock->fl_start) {
			if (flock->fl_type == F_RDLCK) {
				if (type == WRITE) {
					ksmbd_err("not allow write by shared lock\n");
					error = 1;
					goto out;
				}
			} else if (flock->fl_type == F_WRLCK) {
				/* check owner in lock */
				if (flock->fl_file != filp) {
					error = 1;
					ksmbd_err("not allow rw access by exclusive lock from other opens\n");
					goto out;
				}
			}
		}
	}
out:
	spin_unlock(&ctx->flc_lock);
	return error;
}

/**
 * ksmbd_vfs_read() - vfs helper for smb file read
 * @work:	smb work
 * @fid:	file id of open file
 * @count:	read byte count
 * @pos:	file pos
 *
 * Return:	number of read bytes on success, otherwise error
 */
int ksmbd_vfs_read(struct ksmbd_work *work, struct ksmbd_file *fp, size_t count,
		 loff_t *pos)
{
	struct file *filp;
	ssize_t nbytes = 0;
	char *rbuf, *name;
	struct inode *inode;
	char namebuf[NAME_MAX];
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	mm_segment_t old_fs;
#endif

	rbuf = work->aux_payload_buf;
	filp = fp->filp;
	inode = d_inode(filp->f_path.dentry);
	if (S_ISDIR(inode->i_mode))
		return -EISDIR;

	if (unlikely(count == 0))
		return 0;

	if (work->conn->connection_type) {
		if (!(fp->daccess & (FILE_READ_DATA_LE | FILE_EXECUTE_LE))) {
			ksmbd_err("no right to read(%s)\n", FP_FILENAME(fp));
			return -EACCES;
		}
	}

	if (ksmbd_stream_fd(fp))
		return ksmbd_vfs_stream_read(fp, rbuf, pos, count);

	if (!work->tcon->posix_extensions) {
		int ret;

		ret = check_lock_range(filp, *pos, *pos + count - 1,
				READ);
		if (ret) {
			ksmbd_err("unable to read due to lock\n");
			return -EAGAIN;
		}
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	nbytes = vfs_read(filp, rbuf, count, pos);
	set_fs(old_fs);
#else
	nbytes = kernel_read(filp, rbuf, count, pos);
#endif
	if (nbytes < 0) {
		name = d_path(&filp->f_path, namebuf, sizeof(namebuf));
		if (IS_ERR(name))
			name = "(error)";
		ksmbd_err("smb read failed for (%s), err = %zd\n",
				name, nbytes);
		return nbytes;
	}

	filp->f_pos = *pos;
	return nbytes;
}

static int ksmbd_vfs_stream_write(struct ksmbd_file *fp, char *buf, loff_t *pos,
		size_t count)
{
	char *stream_buf = NULL, *wbuf;
	size_t size, v_len;
	int err = 0;

	ksmbd_debug(VFS, "write stream data pos : %llu, count : %zd\n",
			*pos, count);

	size = *pos + count;
	if (size > XATTR_SIZE_MAX) {
		size = XATTR_SIZE_MAX;
		count = (*pos + count) - XATTR_SIZE_MAX;
	}

	v_len = ksmbd_vfs_getcasexattr(fp->filp->f_path.dentry,
				       fp->stream.name,
				       fp->stream.size,
				       &stream_buf);
	if (v_len == -ENOENT) {
		ksmbd_err("not found stream in xattr : %zd\n", v_len);
		err = -ENOENT;
		goto out;
	}

	if (v_len < size) {
		wbuf = ksmbd_alloc(size);
		if (!wbuf) {
			err = -ENOMEM;
			goto out;
		}

		if (v_len > 0)
			memcpy(wbuf, stream_buf, v_len);
		stream_buf = wbuf;
	}

	memcpy(&stream_buf[*pos], buf, count);

	err = ksmbd_vfs_setxattr(fp->filp->f_path.dentry,
				 fp->stream.name,
				 (void *)stream_buf,
				 size,
				 0);
	if (err < 0)
		goto out;

	fp->filp->f_pos = *pos;
	err = 0;
out:
	ksmbd_free(stream_buf);
	return err;
}

/**
 * ksmbd_vfs_write() - vfs helper for smb file write
 * @work:	work
 * @fid:	file id of open file
 * @buf:	buf containing data for writing
 * @count:	read byte count
 * @pos:	file pos
 * @sync:	fsync after write
 * @written:	number of bytes written
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_write(struct ksmbd_work *work, struct ksmbd_file *fp,
		char *buf, size_t count, loff_t *pos, bool sync,
		ssize_t *written)
{
	struct ksmbd_session *sess = work->sess;
	struct file *filp;
	loff_t	offset = *pos;
	int err = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	mm_segment_t old_fs;
#endif

	if (sess->conn->connection_type) {
		if (!(fp->daccess & FILE_WRITE_DATA_LE)) {
			ksmbd_err("no right to write(%s)\n", FP_FILENAME(fp));
			err = -EACCES;
			goto out;
		}
	}

	filp = fp->filp;

	if (ksmbd_stream_fd(fp)) {
		err = ksmbd_vfs_stream_write(fp, buf, pos, count);
		if (!err)
			*written = count;
		goto out;
	}

	if (!work->tcon->posix_extensions) {
		err = check_lock_range(filp, *pos, *pos + count - 1, WRITE);
		if (err) {
			ksmbd_err("unable to write due to lock\n");
			err = -EAGAIN;
			goto out;
		}
	}

	/* Do we need to break any of a levelII oplock? */
	smb_break_all_levII_oplock(work, fp, 1);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_write(filp, buf, count, pos);
	set_fs(old_fs);
#else
	err = kernel_write(filp, buf, count, pos);
#endif

	if (err < 0) {
		ksmbd_debug(VFS, "smb write failed, err = %d\n", err);
		goto out;
	}

	filp->f_pos = *pos;
	*written = err;
	err = 0;
	if (sync) {
		err = vfs_fsync_range(filp, offset, offset + *written, 0);
		if (err < 0)
			ksmbd_err("fsync failed for filename = %s, err = %d\n",
					FP_FILENAME(fp), err);
	}

out:
	return err;
}

/**
 * ksmbd_vfs_getattr() - vfs helper for smb getattr
 * @work:	work
 * @fid:	file id of open file
 * @attrs:	inode attributes
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_getattr(struct path *path, struct kstat *stat)
{
	int err;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	err = vfs_getattr(path, stat, STATX_BTIME, AT_STATX_SYNC_AS_STAT);
#else
	err = vfs_getattr(path, stat);
#endif
	if (err)
		ksmbd_err("getattr failed, err %d\n", err);
	return err;
}

#ifdef CONFIG_SMB_INSECURE_SERVER
/**
 * smb_check_attrs() - sanitize inode attributes
 * @inode:	inode
 * @attrs:	inode attributes
 */
static void smb_check_attrs(struct inode *inode, struct iattr *attrs)
{
	/* sanitize the mode change */
	if (attrs->ia_valid & ATTR_MODE) {
		attrs->ia_mode &= S_IALLUGO;
		attrs->ia_mode |= (inode->i_mode & ~S_IALLUGO);
	}

	/* Revoke setuid/setgid on chown */
	if (!S_ISDIR(inode->i_mode) &&
	    (((attrs->ia_valid & ATTR_UID) &&
	      !uid_eq(attrs->ia_uid, inode->i_uid)) ||
	     ((attrs->ia_valid & ATTR_GID) &&
	      !gid_eq(attrs->ia_gid, inode->i_gid)))) {
		attrs->ia_valid |= ATTR_KILL_PRIV;
		if (attrs->ia_valid & ATTR_MODE) {
			/* we're setting mode too, just clear the s*id bits */
			attrs->ia_mode &= ~S_ISUID;
			if (attrs->ia_mode & 0010)
				attrs->ia_mode &= ~S_ISGID;
		} else {
			/* set ATTR_KILL_* bits and let VFS handle it */
			attrs->ia_valid |= (ATTR_KILL_SUID | ATTR_KILL_SGID);
		}
	}
}

/**
 * ksmbd_vfs_setattr() - vfs helper for smb setattr
 * @work:	work
 * @name:	file name
 * @fid:	file id of open file
 * @attrs:	inode attributes
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_setattr(struct ksmbd_work *work, const char *name, u64 fid,
		struct iattr *attrs)
{
	struct file *filp;
	struct dentry *dentry;
	struct inode *inode;
	struct path path;
	bool update_size = false;
	int err = 0;
	struct ksmbd_file *fp = NULL;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	if (name) {
		err = kern_path(name, 0, &path);
		if (err) {
			ksmbd_revert_fsids(work);
			ksmbd_debug(VFS, "lookup failed for %s, err = %d\n",
					name, err);
			return -ENOENT;
		}
		dentry = path.dentry;
		inode = d_inode(dentry);
	} else {
		fp = ksmbd_lookup_fd_fast(work, fid);
		if (!fp) {
			ksmbd_revert_fsids(work);
			ksmbd_err("failed to get filp for fid %llu\n", fid);
			return -ENOENT;
		}

		filp = fp->filp;
		dentry = filp->f_path.dentry;
		inode = d_inode(dentry);
	}

	if (ksmbd_vfs_inode_permission(dentry, O_WRONLY, false)) {
		err = -EACCES;
		goto out;
	}

	/* no need to update mode of symlink */
	if (S_ISLNK(inode->i_mode))
		attrs->ia_valid &= ~ATTR_MODE;

	/* skip setattr, if nothing to update */
	if (!attrs->ia_valid) {
		err = 0;
		goto out;
	}

	smb_check_attrs(inode, attrs);
	if (attrs->ia_valid & ATTR_SIZE) {
		err = get_write_access(inode);
		if (err)
			goto out;

		err = locks_verify_truncate(inode, NULL, attrs->ia_size);
		if (err) {
			put_write_access(inode);
			goto out;
		}
		update_size = true;
	}

	attrs->ia_valid |= ATTR_CTIME;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 21)
	inode_lock(inode);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	err = notify_change(&init_user_ns, dentry, attrs, NULL);
#else
	err = notify_change(dentry, attrs, NULL);
#endif
	inode_unlock(inode);
#else
	mutex_lock(&inode->i_mutex);
	err = notify_change(dentry, attrs, NULL);
	mutex_unlock(&inode->i_mutex);
#endif

	if (update_size)
		put_write_access(inode);

	if (!err) {
		sync_inode_metadata(inode, 1);
		ksmbd_debug(VFS, "fid %llu, setattr done\n", fid);
	}

out:
	if (name)
		path_put(&path);
	ksmbd_fd_put(work, fp);
	ksmbd_revert_fsids(work);
	return err;
}

/**
 * ksmbd_vfs_symlink() - vfs helper for creating smb symlink
 * @name:	source file name
 * @symname:	symlink name
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_symlink(struct ksmbd_work *work, const char *name,
		const char *symname)
{
	struct path path;
	struct dentry *dentry;
	int err;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	dentry = kern_path_create(AT_FDCWD, symname, &path, 0);
	if (IS_ERR(dentry)) {
		ksmbd_revert_fsids(work);
		err = PTR_ERR(dentry);
		ksmbd_err("path create failed for %s, err %d\n", name, err);
		return err;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	err = vfs_symlink(&init_user_ns, d_inode(dentry->d_parent), dentry, name);
#else
	err = vfs_symlink(d_inode(dentry->d_parent), dentry, name);
#endif
	if (err && (err != -EEXIST || err != -ENOSPC))
		ksmbd_debug(VFS, "failed to create symlink, err %d\n", err);

	done_path_create(&path, dentry);
	ksmbd_revert_fsids(work);
	return err;
}

/**
 * ksmbd_vfs_readlink() - vfs helper for reading value of symlink
 * @path:	path of symlink
 * @buf:	destination buffer for symlink value
 * @lenp:	destination buffer length
 *
 * Return:	symlink value length on success, otherwise error
 */
int ksmbd_vfs_readlink(struct path *path, char *buf, int lenp)
{
	struct inode *inode;
	int err;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	const char *link;
	DEFINE_DELAYED_CALL(done);
	int len;
#else
	mm_segment_t old_fs;
#endif

	if (!path)
		return -ENOENT;

	inode = d_inode(path->dentry);
	if (!S_ISLNK(inode->i_mode))
		return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	link = vfs_get_link(path->dentry, &done);
	if (IS_ERR(link)) {
		err = PTR_ERR(link);
		ksmbd_err("readlink failed, err = %d\n", err);
		return err;
	}

	len = strlen(link);
	if (len > lenp)
		len = lenp;

	memcpy(buf, link, len);
	do_delayed_call(&done);

	return 0;
#else
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = inode->i_op->readlink(path->dentry, (char __user *)buf, lenp);
	set_fs(old_fs);
	if (err < 0)
		ksmbd_err("readlink failed, err = %d\n", err);

	return err;
#endif
}

int ksmbd_vfs_readdir_name(struct ksmbd_work *work, struct ksmbd_kstat *ksmbd_kstat,
		const char *de_name, int de_name_len, const char *dir_path)
{
	struct path path;
	int rc, file_pathlen, dir_pathlen;
	char *name;

	dir_pathlen = strlen(dir_path);
	/* 1 for '/'*/
	file_pathlen = dir_pathlen +  de_name_len + 1;
	name = kmalloc(file_pathlen + 1, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	memcpy(name, dir_path, dir_pathlen);
	memset(name + dir_pathlen, '/', 1);
	memcpy(name + dir_pathlen + 1, de_name, de_name_len);
	name[file_pathlen] = '\0';

	rc = ksmbd_vfs_kern_path(name, LOOKUP_FOLLOW, &path, 1);
	if (rc) {
		ksmbd_err("lookup failed: %s [%d]\n", name, rc);
		kfree(name);
		return -ENOMEM;
	}

	ksmbd_vfs_fill_dentry_attrs(work, path.dentry, ksmbd_kstat);
	path_put(&path);
	kfree(name);
	return 0;
}
#endif

/**
 * ksmbd_vfs_fsync() - vfs helper for smb fsync
 * @work:	work
 * @fid:	file id of open file
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_fsync(struct ksmbd_work *work, u64 fid, u64 p_id)
{
	struct ksmbd_file *fp;
	int err;

	fp = ksmbd_lookup_fd_slow(work, fid, p_id);
	if (!fp) {
		ksmbd_err("failed to get filp for fid %llu\n", fid);
		return -ENOENT;
	}
	err = vfs_fsync(fp->filp, 0);
	if (err < 0)
		ksmbd_err("smb fsync failed, err = %d\n", err);
	ksmbd_fd_put(work, fp);
	return err;
}

/**
 * ksmbd_vfs_remove_file() - vfs helper for smb rmdir or unlink
 * @name:	absolute directory or file name
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_remove_file(struct ksmbd_work *work, char *name)
{
	struct path parent;
	struct dentry *dir, *dentry;
	char *last;
	int err;

	last = extract_last_component(name);
	if (!last)
		return -EINVAL;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	err = kern_path(name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &parent);
	if (err) {
		ksmbd_debug(VFS, "can't get %s, err %d\n", name, err);
		ksmbd_revert_fsids(work);
		rollback_path_modification(last);
		return err;
	}

	dir = parent.dentry;
	if (!d_inode(dir))
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 21)
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
#else
	mutex_lock_nested(&d_inode(dir)->i_mutex, I_MUTEX_PARENT);
#endif
	dentry = lookup_one_len(last, dir, strlen(last));
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		ksmbd_debug(VFS, "%s: lookup failed, err %d\n", last, err);
		goto out_err;
	}

	if (!d_inode(dentry) || !d_inode(dentry)->i_nlink) {
		dput(dentry);
		err = -ENOENT;
		goto out_err;
	}

	if (S_ISDIR(d_inode(dentry)->i_mode)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		err = vfs_rmdir(&init_user_ns, d_inode(dir), dentry);
#else
		err = vfs_rmdir(d_inode(dir), dentry);
#endif
		if (err && err != -ENOTEMPTY)
			ksmbd_debug(VFS, "%s: rmdir failed, err %d\n", name,
				err);
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		err = vfs_unlink(&init_user_ns, d_inode(dir), dentry, NULL);
#else
		err = vfs_unlink(d_inode(dir), dentry, NULL);
#endif
		if (err)
			ksmbd_debug(VFS, "%s: unlink failed, err %d\n", name,
				err);
	}

	dput(dentry);
out_err:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 21)
	inode_unlock(d_inode(dir));
#else
	mutex_unlock(&d_inode(dir)->i_mutex);
#endif
out:
	rollback_path_modification(last);
	path_put(&parent);
	ksmbd_revert_fsids(work);
	return err;
}

/**
 * ksmbd_vfs_link() - vfs helper for creating smb hardlink
 * @oldname:	source file name
 * @newname:	hardlink name
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_link(struct ksmbd_work *work, const char *oldname,
		const char *newname)
{
	struct path oldpath, newpath;
	struct dentry *dentry;
	int err;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	err = kern_path(oldname, LOOKUP_FOLLOW, &oldpath);
	if (err) {
		ksmbd_err("cannot get linux path for %s, err = %d\n",
				oldname, err);
		goto out1;
	}

	dentry = kern_path_create(AT_FDCWD, newname, &newpath,
			LOOKUP_FOLLOW | LOOKUP_REVAL);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		ksmbd_err("path create err for %s, err %d\n", newname, err);
		goto out2;
	}

	err = -EXDEV;
	if (oldpath.mnt != newpath.mnt) {
		ksmbd_err("vfs_link failed err %d\n", err);
		goto out3;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	err = vfs_link(oldpath.dentry, &init_user_ns, d_inode(newpath.dentry),
			dentry, NULL);
#else
	err = vfs_link(oldpath.dentry, d_inode(newpath.dentry), dentry, NULL);
#endif
	if (err)
		ksmbd_debug(VFS, "vfs_link failed err %d\n", err);

out3:
	done_path_create(&newpath, dentry);
out2:
	path_put(&oldpath);
out1:
	ksmbd_revert_fsids(work);
	return err;
}

static int __ksmbd_vfs_rename(struct ksmbd_work *work,
		struct dentry *src_dent_parent, struct dentry *src_dent,
		struct dentry *dst_dent_parent, struct dentry *trap_dent,
		char *dst_name)
{
	struct dentry *dst_dent;
	int err;

	if (!work->tcon->posix_extensions) {
		spin_lock(&src_dent->d_lock);
		list_for_each_entry(dst_dent, &src_dent->d_subdirs, d_child) {
			struct ksmbd_file *child_fp;

			if (d_really_is_negative(dst_dent))
				continue;

			child_fp = ksmbd_lookup_fd_inode(d_inode(dst_dent));
			if (child_fp) {
				spin_unlock(&src_dent->d_lock);
				ksmbd_debug(VFS, "Forbid rename, sub file/dir is in use\n");
				return -EACCES;
			}
		}
		spin_unlock(&src_dent->d_lock);
	}

	if (d_really_is_negative(src_dent_parent))
		return -ENOENT;
	if (d_really_is_negative(dst_dent_parent))
		return -ENOENT;
	if (d_really_is_negative(src_dent))
		return -ENOENT;
	if (src_dent == trap_dent)
		return -EINVAL;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	dst_dent = lookup_one_len(dst_name, dst_dent_parent, strlen(dst_name));
	err = PTR_ERR(dst_dent);
	if (IS_ERR(dst_dent)) {
		ksmbd_err("lookup failed %s [%d]\n", dst_name, err);
		goto out;
	}

	err = -ENOTEMPTY;
	if (dst_dent != trap_dent && !d_really_is_positive(dst_dent)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		struct renamedata rd = {
			.old_mnt_userns	= &init_user_ns,
			.old_dir	= d_inode(src_dent_parent),
			.old_dentry	= src_dent,
			.new_mnt_userns	= &init_user_ns,
			.new_dir	= d_inode(dst_dent_parent),
			.new_dentry	= dst_dent,
		};
		err = vfs_rename(&rd);
#else
		err = vfs_rename(d_inode(src_dent_parent),
				 src_dent,
				 d_inode(dst_dent_parent),
				 dst_dent,
				 NULL,
				 0);
#endif
	}
	if (err)
		ksmbd_err("vfs_rename failed err %d\n", err);
	if (dst_dent)
		dput(dst_dent);
out:
	ksmbd_revert_fsids(work);
	return err;
}

int ksmbd_vfs_fp_rename(struct ksmbd_work *work, struct ksmbd_file *fp,
		char *newname)
{
	struct path dst_path;
	struct dentry *src_dent_parent, *dst_dent_parent;
	struct dentry *src_dent, *trap_dent;
	char *dst_name;
	int err;

	dst_name = extract_last_component(newname);
	if (!dst_name)
		return -EINVAL;

	src_dent_parent = dget_parent(fp->filp->f_path.dentry);
	if (!src_dent_parent)
		return -EINVAL;

	src_dent = fp->filp->f_path.dentry;
	dget(src_dent);

	err = kern_path(newname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dst_path);
	if (err) {
		ksmbd_debug(VFS, "Cannot get path for %s [%d]\n", newname, err);
		goto out;
	}
	dst_dent_parent = dst_path.dentry;
	dget(dst_dent_parent);

	trap_dent = lock_rename(src_dent_parent, dst_dent_parent);
	err = __ksmbd_vfs_rename(work,
				 src_dent_parent,
				 src_dent,
				 dst_dent_parent,
				 trap_dent,
				 dst_name);
	unlock_rename(src_dent_parent, dst_dent_parent);
	dput(dst_dent_parent);
	path_put(&dst_path);
out:
	dput(src_dent);
	dput(src_dent_parent);
	return err;
}

#ifdef CONFIG_SMB_INSECURE_SERVER
int ksmbd_vfs_rename_slowpath(struct ksmbd_work *work, char *oldname, char *newname)
{
	struct path dst_path, src_path;
	struct dentry *src_dent_parent, *dst_dent_parent;
	struct dentry *src_dent = NULL, *trap_dent;
	char *src_name, *dst_name;
	int err;

	src_name = extract_last_component(oldname);
	if (!src_name)
		return -EINVAL;
	dst_name = extract_last_component(newname);
	if (!dst_name)
		return -EINVAL;

	err = kern_path(oldname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &src_path);
	if (err) {
		ksmbd_err("Cannot get path for %s [%d]\n", oldname, err);
		return err;
	}
	src_dent_parent = src_path.dentry;
	dget(src_dent_parent);

	err = kern_path(newname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dst_path);
	if (err) {
		ksmbd_err("Cannot get path for %s [%d]\n", newname, err);
		dput(src_dent_parent);
		path_put(&src_path);
		return err;
	}
	dst_dent_parent = dst_path.dentry;
	dget(dst_dent_parent);

	trap_dent = lock_rename(src_dent_parent, dst_dent_parent);
	src_dent = lookup_one_len(src_name, src_dent_parent, strlen(src_name));
	err = PTR_ERR(src_dent);
	if (IS_ERR(src_dent)) {
		src_dent = NULL;
		ksmbd_err("%s lookup failed with error = %d\n", src_name, err);
		goto out;
	}

	err = __ksmbd_vfs_rename(work, src_dent_parent,
				 src_dent,
				 dst_dent_parent,
				 trap_dent,
				 dst_name);
out:
	if (src_dent)
		dput(src_dent);
	dput(dst_dent_parent);
	dput(src_dent_parent);
	unlock_rename(src_dent_parent, dst_dent_parent);
	path_put(&src_path);
	path_put(&dst_path);
	return err;
}
#else
int ksmbd_vfs_rename_slowpath(struct ksmbd_work *work, char *oldname,
		char *newname)
{
	return 0;
}
#endif

/**
 * ksmbd_vfs_truncate() - vfs helper for smb file truncate
 * @work:	work
 * @name:	old filename
 * @fid:	file id of old file
 * @size:	truncate to given size
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_truncate(struct ksmbd_work *work, const char *name,
		struct ksmbd_file *fp, loff_t size)
{
	struct path path;
	int err = 0;

	if (name) {
		err = kern_path(name, 0, &path);
		if (err) {
			ksmbd_err("cannot get linux path for %s, err %d\n",
					name, err);
			return err;
		}
		err = vfs_truncate(&path, size);
		if (err)
			ksmbd_err("truncate failed for %s err %d\n",
					name, err);
		path_put(&path);
	} else {
		struct file *filp;

		filp = fp->filp;

		/* Do we need to break any of a levelII oplock? */
		smb_break_all_levII_oplock(work, fp, 1);

		if (!work->tcon->posix_extensions) {
			struct inode *inode = file_inode(filp);

			if (size < inode->i_size) {
				err = check_lock_range(filp, size,
						inode->i_size - 1, WRITE);
			} else {
				err = check_lock_range(filp, inode->i_size,
						size - 1, WRITE);
			}

			if (err) {
				ksmbd_err("failed due to lock\n");
				return -EAGAIN;
			}
		}

		err = vfs_truncate(&filp->f_path, size);
		if (err)
			ksmbd_err("truncate failed for filename : %s err %d\n",
					fp->filename, err);
	}

	return err;
}

/**
 * ksmbd_vfs_listxattr() - vfs helper for smb list extended attributes
 * @dentry:	dentry of file for listing xattrs
 * @list:	destination buffer
 * @size:	destination buffer length
 *
 * Return:	xattr list length on success, otherwise error
 */
ssize_t ksmbd_vfs_listxattr(struct dentry *dentry, char **list)
{
	ssize_t size;
	char *vlist = NULL;

	size = vfs_listxattr(dentry, NULL, 0);
	if (size <= 0)
		return size;

	vlist = ksmbd_alloc(size);
	if (!vlist)
		return -ENOMEM;

	*list = vlist;
	size = vfs_listxattr(dentry, vlist, size);
	if (size < 0) {
		ksmbd_debug(VFS, "listxattr failed\n");
		ksmbd_vfs_xattr_free(vlist);
		*list = NULL;
	}

	return size;
}

static ssize_t ksmbd_vfs_xattr_len(struct dentry *dentry, char *xattr_name)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return vfs_getxattr(&init_user_ns, dentry, xattr_name, NULL, 0);
#else
	return vfs_getxattr(dentry, xattr_name, NULL, 0);
#endif
}

/**
 * ksmbd_vfs_getxattr() - vfs helper for smb get extended attributes value
 * @dentry:	dentry of file for getting xattrs
 * @xattr_name:	name of xattr name to query
 * @xattr_buf:	destination buffer xattr value
 *
 * Return:	read xattr value length on success, otherwise error
 */
ssize_t ksmbd_vfs_getxattr(struct dentry *dentry, char *xattr_name,
		char **xattr_buf)
{
	ssize_t xattr_len;
	char *buf;

	*xattr_buf = NULL;
	xattr_len = ksmbd_vfs_xattr_len(dentry, xattr_name);
	if (xattr_len < 0)
		return xattr_len;

	buf = kmalloc(xattr_len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	xattr_len = vfs_getxattr(&init_user_ns, dentry, xattr_name, (void *)buf,
			xattr_len);
#else
	xattr_len = vfs_getxattr(dentry, xattr_name, (void *)buf, xattr_len);
#endif
	if (xattr_len > 0)
		*xattr_buf = buf;
	else
		kfree(buf);
	return xattr_len;
}

/**
 * ksmbd_vfs_setxattr() - vfs helper for smb set extended attributes value
 * @dentry:	dentry to set XATTR at
 * @name:	xattr name for setxattr
 * @value:	xattr value to set
 * @size:	size of xattr value
 * @flags:	destination buffer length
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_setxattr(struct dentry *dentry, const char *attr_name,
		const void *attr_value, size_t attr_size, int flags)
{
	int err;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	err = vfs_setxattr(&init_user_ns, dentry,
#else
	err = vfs_setxattr(dentry,
#endif
			   attr_name,
			   attr_value,
			   attr_size,
			   flags);
	if (err)
		ksmbd_debug(VFS, "setxattr failed, err %d\n", err);
	return err;
}

#ifdef CONFIG_SMB_INSECURE_SERVER
int ksmbd_vfs_fsetxattr(struct ksmbd_work *work, const char *filename,
		const char *attr_name, const void *attr_value, size_t attr_size,
		int flags)
{
	struct path path;
	int err;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	err = kern_path(filename, 0, &path);
	if (err) {
		ksmbd_revert_fsids(work);
		ksmbd_debug(VFS, "cannot get linux path %s, err %d\n",
				filename, err);
		return err;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	err = vfs_setxattr(&init_user_ns, path.dentry,
#else
	err = vfs_setxattr(path.dentry,
#endif
			   attr_name,
			   attr_value,
			   attr_size,
			   flags);
	if (err)
		ksmbd_debug(VFS, "setxattr failed, err %d\n", err);
	path_put(&path);
	ksmbd_revert_fsids(work);
	return err;
}
#endif

int ksmbd_vfs_remove_acl_xattrs(struct dentry *dentry)
{
	char *name, *xattr_list = NULL;
	ssize_t xattr_list_len;
	int err = 0;

	xattr_list_len = ksmbd_vfs_listxattr(dentry, &xattr_list);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		ksmbd_debug(SMB, "empty xattr in the file\n");
		goto out;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		ksmbd_debug(SMB, "%s, len %zd\n", name, strlen(name));

		if (!strncmp(name, XATTR_NAME_POSIX_ACL_ACCESS,
			     sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1) ||
		    !strncmp(name, XATTR_NAME_POSIX_ACL_DEFAULT,
			     sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1)) {
			err = ksmbd_vfs_remove_xattr(dentry, name);
			if (err)
				ksmbd_debug(SMB,
					"remove acl xattr failed : %s\n", name);
		}
	}
out:
	ksmbd_vfs_xattr_free(xattr_list);
	return err;
}

int ksmbd_vfs_remove_sd_xattrs(struct dentry *dentry)
{
	char *name, *xattr_list = NULL;
	ssize_t xattr_list_len;
	int err = 0;

	xattr_list_len = ksmbd_vfs_listxattr(dentry, &xattr_list);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		ksmbd_debug(SMB, "empty xattr in the file\n");
		goto out;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		ksmbd_debug(SMB, "%s, len %zd\n", name, strlen(name));

		if (!strncmp(name, XATTR_NAME_SD, XATTR_NAME_SD_LEN)) {
			err = ksmbd_vfs_remove_xattr(dentry, name);
			if (err)
				ksmbd_debug(SMB, "remove xattr failed : %s\n", name);
		}
	}
out:
	ksmbd_vfs_xattr_free(xattr_list);
	return err;
}

static struct xattr_smb_acl *ksmbd_vfs_make_xattr_posix_acl(struct inode *inode,
		int acl_type)
{
	struct xattr_smb_acl *smb_acl = NULL;
	struct posix_acl *posix_acls;
	struct posix_acl_entry *pa_entry;
	struct xattr_acl_entry *xa_entry;
	int i;

	posix_acls = ksmbd_vfs_get_acl(inode, acl_type);
	if (!posix_acls)
		return NULL;

	smb_acl = kzalloc(sizeof(struct xattr_smb_acl) +
			  sizeof(struct xattr_acl_entry) * posix_acls->a_count,
			  GFP_KERNEL);
	if (!smb_acl)
		goto out;

	smb_acl->count = posix_acls->a_count;
	pa_entry = posix_acls->a_entries;
	xa_entry = smb_acl->entries;
	for (i = 0; i < posix_acls->a_count; i++, pa_entry++, xa_entry++) {
		switch (pa_entry->e_tag) {
		case ACL_USER:
			xa_entry->type = SMB_ACL_USER;
			xa_entry->uid = from_kuid(&init_user_ns, pa_entry->e_uid);
			break;
		case ACL_USER_OBJ:
			xa_entry->type = SMB_ACL_USER_OBJ;
			break;
		case ACL_GROUP:
			xa_entry->type = SMB_ACL_GROUP;
			xa_entry->gid = from_kgid(&init_user_ns, pa_entry->e_gid);
			break;
		case ACL_GROUP_OBJ:
			xa_entry->type = SMB_ACL_GROUP_OBJ;
			break;
		case ACL_OTHER:
			xa_entry->type = SMB_ACL_OTHER;
			break;
		case ACL_MASK:
			xa_entry->type = SMB_ACL_MASK;
			break;
		default:
			ksmbd_err("unknown type : 0x%x\n", pa_entry->e_tag);
			goto out;
		}

		if (pa_entry->e_perm & ACL_READ)
			xa_entry->perm |= SMB_ACL_READ;
		if (pa_entry->e_perm & ACL_WRITE)
			xa_entry->perm |= SMB_ACL_WRITE;
		if (pa_entry->e_perm & ACL_EXECUTE)
			xa_entry->perm |= SMB_ACL_EXECUTE;
	}
out:
	posix_acl_release(posix_acls);
	return smb_acl;
}

int ksmbd_vfs_set_sd_xattr(struct ksmbd_conn *conn, struct dentry *dentry,
		struct smb_ntsd *pntsd, int len)
{
	int rc;
	struct ndr sd_ndr = {0}, acl_ndr = {0};
	struct xattr_ntacl acl = {0};
	struct xattr_smb_acl *smb_acl, *def_smb_acl = NULL;
	struct inode *inode = dentry->d_inode;

	acl.version = 4;
	acl.hash_type = XATTR_SD_HASH_TYPE_SHA256;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	acl.current_time = ksmbd_UnixTimeToNT(current_time(dentry->d_inode));
#else
	acl.current_time = ksmbd_UnixTimeToNT(CURRENT_TIME);
#endif

	memcpy(acl.desc, "posix_acl", 9);
	acl.desc_len = 10;

	pntsd->osidoffset =
		cpu_to_le32(le32_to_cpu(pntsd->osidoffset) + NDR_NTSD_OFFSETOF);
	pntsd->gsidoffset =
		cpu_to_le32(le32_to_cpu(pntsd->gsidoffset) + NDR_NTSD_OFFSETOF);
	pntsd->dacloffset =
		cpu_to_le32(le32_to_cpu(pntsd->dacloffset) + NDR_NTSD_OFFSETOF);

	acl.sd_buf = (char *)pntsd;
	acl.sd_size = len;

	rc = ksmbd_gen_sd_hash(conn, acl.sd_buf, acl.sd_size, acl.hash);
	if (rc) {
		ksmbd_err("failed to generate hash for ndr acl\n");
		return rc;
	}

	smb_acl = ksmbd_vfs_make_xattr_posix_acl(dentry->d_inode, ACL_TYPE_ACCESS);
	if (S_ISDIR(inode->i_mode))
		def_smb_acl = ksmbd_vfs_make_xattr_posix_acl(dentry->d_inode,
				ACL_TYPE_DEFAULT);

	rc = ndr_encode_posix_acl(&acl_ndr, inode, smb_acl, def_smb_acl);
	if (rc) {
		ksmbd_err("failed to encode ndr to posix acl\n");
		goto out;
	}

	rc = ksmbd_gen_sd_hash(conn, acl_ndr.data, acl_ndr.offset,
			acl.posix_acl_hash);
	if (rc) {
		ksmbd_err("failed to generate hash for ndr acl\n");
		goto out;
	}

	rc = ndr_encode_v4_ntacl(&sd_ndr, &acl);
	if (rc) {
		ksmbd_err("failed to encode ndr to posix acl\n");
		goto out;
	}

	rc = ksmbd_vfs_setxattr(dentry, XATTR_NAME_SD, sd_ndr.data,
			sd_ndr.offset, 0);
	if (rc < 0)
		ksmbd_err("Failed to store XATTR ntacl :%d\n", rc);

	kfree(sd_ndr.data);
out:
	kfree(acl_ndr.data);
	kfree(smb_acl);
	kfree(def_smb_acl);
	return rc;
}

int ksmbd_vfs_get_sd_xattr(struct ksmbd_conn *conn, struct dentry *dentry,
		struct smb_ntsd **pntsd)
{
	int rc;
	struct ndr n;

	rc = ksmbd_vfs_getxattr(dentry, XATTR_NAME_SD, &n.data);
	if (rc > 0) {
		struct inode *inode = dentry->d_inode;
		struct ndr acl_ndr = {0};
		struct xattr_ntacl acl;
		struct xattr_smb_acl *smb_acl = NULL, *def_smb_acl = NULL;
		__u8 cmp_hash[XATTR_SD_HASH_SIZE] = {0};

		n.length = rc;
		rc = ndr_decode_v4_ntacl(&n, &acl);
		if (rc)
			return rc;

		smb_acl = ksmbd_vfs_make_xattr_posix_acl(inode,
				ACL_TYPE_ACCESS);
		if (S_ISDIR(inode->i_mode))
			def_smb_acl = ksmbd_vfs_make_xattr_posix_acl(inode,
					ACL_TYPE_DEFAULT);

		rc = ndr_encode_posix_acl(&acl_ndr, inode, smb_acl, def_smb_acl);
		if (rc) {
			ksmbd_err("failed to encode ndr to posix acl\n");
			goto out;
		}

		rc = ksmbd_gen_sd_hash(conn, acl_ndr.data, acl_ndr.offset,
				cmp_hash);
		if (rc) {
			ksmbd_err("failed to generate hash for ndr acl\n");
			goto out;
		}

		if (memcmp(cmp_hash, acl.posix_acl_hash, XATTR_SD_HASH_SIZE)) {
			ksmbd_err("hash value diff\n");
			rc = -EINVAL;
			goto out;
		}

		*pntsd = acl.sd_buf;
		(*pntsd)->osidoffset =
			cpu_to_le32(le32_to_cpu((*pntsd)->osidoffset) - NDR_NTSD_OFFSETOF);
		(*pntsd)->gsidoffset =
			cpu_to_le32(le32_to_cpu((*pntsd)->gsidoffset) - NDR_NTSD_OFFSETOF);
		(*pntsd)->dacloffset =
			cpu_to_le32(le32_to_cpu((*pntsd)->dacloffset) - NDR_NTSD_OFFSETOF);

		rc = acl.sd_size;
out:
		kfree(n.data);
		kfree(acl_ndr.data);
		kfree(smb_acl);
		kfree(def_smb_acl);
	}

	return rc;
}

int ksmbd_vfs_set_dos_attrib_xattr(struct dentry *dentry,
		struct xattr_dos_attrib *da)
{
	struct ndr n;
	int err;

	err = ndr_encode_dos_attr(&n, da);
	if (err)
		return err;

	err = ksmbd_vfs_setxattr(dentry,
			XATTR_NAME_DOS_ATTRIBUTE,
			(void *)n.data,
			n.offset,
			0);
	if (err)
		ksmbd_debug(SMB, "failed to store dos attribute in xattr\n");
	kfree(n.data);

	return err;
}

int ksmbd_vfs_get_dos_attrib_xattr(struct dentry *dentry,
		struct xattr_dos_attrib *da)
{
	struct ndr n;
	int err;

	err = ksmbd_vfs_getxattr(dentry,
			XATTR_NAME_DOS_ATTRIBUTE,
			(char **)&n.data);
	if (err > 0) {
		n.length = err;
		if (ndr_decode_dos_attr(&n, da))
			err = -EINVAL;
		ksmbd_free(n.data);
	} else {
		ksmbd_debug(SMB, "failed to load dos attribute in xattr\n");
	}

	return err;
}

struct posix_acl *ksmbd_vfs_posix_acl_alloc(int count, gfp_t flags)
{
#if IS_ENABLED(CONFIG_FS_POSIX_ACL)
	return posix_acl_alloc(count, flags);
#else
	return NULL;
#endif
}

struct posix_acl *ksmbd_vfs_get_acl(struct inode *inode, int type)
{
#if IS_ENABLED(CONFIG_FS_POSIX_ACL)
	return get_acl(inode, type);
#else
	return NULL;
#endif
}

int ksmbd_vfs_set_posix_acl(struct inode *inode, int type,
		struct posix_acl *acl)
{
#if IS_ENABLED(CONFIG_FS_POSIX_ACL)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 4, 21)
	int ret;

	if (!IS_POSIXACL(inode))
		return -EOPNOTSUPP;
	if (!inode->i_op->set_acl)
		return -EOPNOTSUPP;

	if (type == ACL_TYPE_DEFAULT && !S_ISDIR(inode->i_mode))
		return -EACCES;
	if (!inode_owner_or_capable(inode))
		return -EPERM;
	if (!acl)
		return -EINVAL;

	ret = posix_acl_valid(acl);
	if (ret)
		return ret;
	return inode->i_op->set_acl(inode, acl, type);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return set_posix_acl(&init_user_ns, inode, type, acl);
#else
	return set_posix_acl(inode, type, acl);
#endif
#endif
#else
	return -EOPNOTSUPP;
#endif
}

/**
 * ksmbd_vfs_set_fadvise() - convert smb IO caching options to linux options
 * @filp:	file pointer for IO
 * @options:	smb IO options
 */
void ksmbd_vfs_set_fadvise(struct file *filp, __le32 option)
{
	struct address_space *mapping;

	mapping = filp->f_mapping;

	if (!option || !mapping)
		return;

	if (option & FILE_WRITE_THROUGH_LE) {
		filp->f_flags |= O_SYNC;
	} else if (option & FILE_SEQUENTIAL_ONLY_LE) {
		filp->f_ra.ra_pages = inode_to_bdi(mapping->host)->ra_pages * 2;
		spin_lock(&filp->f_lock);
		filp->f_mode &= ~FMODE_RANDOM;
		spin_unlock(&filp->f_lock);
	} else if (option & FILE_RANDOM_ACCESS_LE) {
		spin_lock(&filp->f_lock);
		filp->f_mode |= FMODE_RANDOM;
		spin_unlock(&filp->f_lock);
	}
}

/**
 * ksmbd_vfs_lock() - vfs helper for smb file locking
 * @filp:	the file to apply the lock to
 * @cmd:	type of locking operation (F_SETLK, F_GETLK, etc.)
 * @flock:	The lock to be applied
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_lock(struct file *filp, int cmd,
			struct file_lock *flock)
{
	ksmbd_debug(VFS, "calling vfs_lock_file\n");
	return vfs_lock_file(filp, cmd, flock, NULL);
}

int ksmbd_vfs_readdir(struct file *file, struct ksmbd_readdir_data *rdata)
{
	return iterate_dir(file, &rdata->ctx);
}

int ksmbd_vfs_alloc_size(struct ksmbd_work *work, struct ksmbd_file *fp,
		loff_t len)
{
	smb_break_all_levII_oplock(work, fp, 1);
	return vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0, len);
}

int ksmbd_vfs_zero_data(struct ksmbd_work *work, struct ksmbd_file *fp,
		loff_t off, loff_t len)
{
	smb_break_all_levII_oplock(work, fp, 1);
	if (fp->f_ci->m_fattr & ATTR_SPARSE_FILE_LE)
		return vfs_fallocate(fp->filp,
			FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, off, len);

	return vfs_fallocate(fp->filp, FALLOC_FL_ZERO_RANGE, off, len);
}

int ksmbd_vfs_fqar_lseek(struct ksmbd_file *fp, loff_t start, loff_t length,
		struct file_allocated_range_buffer *ranges, int in_count,
		int *out_count)
{
	struct file *f = fp->filp;
	struct inode *inode = FP_INODE(fp);
	loff_t maxbytes = (u64)inode->i_sb->s_maxbytes, end;
	loff_t extent_start, extent_end;
	int ret = 0;

	if (start > maxbytes)
		return -EFBIG;

	if (!in_count)
		return 0;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (length > maxbytes || (maxbytes - length) < start)
		length = maxbytes - start;

	if (start + length > inode->i_size)
		length = inode->i_size - start;

	*out_count = 0;
	end = start + length;
	while (start < end && *out_count < in_count) {
		extent_start = f->f_op->llseek(f, start, SEEK_DATA);
		if (extent_start < 0) {
			if (extent_start != -ENXIO)
				ret = (int)extent_start;
			break;
		}

		if (extent_start >= end)
			break;

		extent_end = f->f_op->llseek(f, extent_start, SEEK_HOLE);
		if (extent_end < 0) {
			if (extent_end != -ENXIO)
				ret = (int)extent_end;
			break;
		} else if (extent_start >= extent_end) {
			break;
		}

		ranges[*out_count].file_offset = cpu_to_le64(extent_start);
		ranges[(*out_count)++].length =
			cpu_to_le64(min(extent_end, end) - extent_start);

		start = extent_end;
	}

	return ret;
}

int ksmbd_vfs_remove_xattr(struct dentry *dentry, char *attr_name)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return vfs_removexattr(&init_user_ns, dentry, attr_name);
#else
	return vfs_removexattr(dentry, attr_name);
#endif
}

void ksmbd_vfs_xattr_free(char *xattr)
{
	ksmbd_free(xattr);
}

int ksmbd_vfs_unlink(struct dentry *dir, struct dentry *dentry)
{
	int err = 0;

	dget(dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 21)
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
#else
	mutex_lock_nested(&d_inode(dir)->i_mutex, I_MUTEX_PARENT);
#endif
	if (!d_inode(dentry) || !d_inode(dentry)->i_nlink) {
		err = -ENOENT;
		goto out;
	}

	if (S_ISDIR(d_inode(dentry)->i_mode))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		err = vfs_rmdir(&init_user_ns, d_inode(dir), dentry);
	else
		err = vfs_unlink(&init_user_ns, d_inode(dir), dentry, NULL);
#else
		err = vfs_rmdir(d_inode(dir), dentry);
	else
		err = vfs_unlink(d_inode(dir), dentry, NULL);
#endif

out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 21)
	inode_unlock(d_inode(dir));
#else
	mutex_unlock(&d_inode(dir)->i_mutex);
#endif
	dput(dentry);
	if (err)
		ksmbd_debug(VFS, "failed to delete, err %d\n", err);

	return err;
}

/*
 * ksmbd_vfs_get_logical_sector_size() - get logical sector size from inode
 * @inode: inode
 *
 * Return: logical sector size
 */
unsigned short ksmbd_vfs_logical_sector_size(struct inode *inode)
{
	struct request_queue *q;
	unsigned short ret_val = 512;

	if (!inode->i_sb->s_bdev)
		return ret_val;

	q = inode->i_sb->s_bdev->bd_disk->queue;

	if (q && q->limits.logical_block_size)
		ret_val = q->limits.logical_block_size;

	return ret_val;
}

/*
 * ksmbd_vfs_get_smb2_sector_size() - get fs sector sizes
 * @inode: inode
 * @fs_ss: fs sector size struct
 */
void ksmbd_vfs_smb2_sector_size(struct inode *inode,
		struct ksmbd_fs_sector_size *fs_ss)
{
	struct request_queue *q;

	fs_ss->logical_sector_size = 512;
	fs_ss->physical_sector_size = 512;
	fs_ss->optimal_io_size = 512;

	if (!inode->i_sb->s_bdev)
		return;

	q = inode->i_sb->s_bdev->bd_disk->queue;

	if (q) {
		if (q->limits.logical_block_size)
			fs_ss->logical_sector_size =
				q->limits.logical_block_size;
		if (q->limits.physical_block_size)
			fs_ss->physical_sector_size =
				q->limits.physical_block_size;
		if (q->limits.io_opt)
			fs_ss->optimal_io_size = q->limits.io_opt;
	}
}

#ifdef CONFIG_SMB_INSECURE_SERVER
/**
 * ksmbd_vfs_dentry_open() - open a dentry and provide fid for it
 * @work:	smb work ptr
 * @path:	path of dentry to be opened
 * @flags:	open flags
 * @ret_id:	fid returned on this
 * @option:	file access pattern options for fadvise
 * @fexist:	file already present or not
 *
 * Return:	0 on success, otherwise error
 */
struct ksmbd_file *ksmbd_vfs_dentry_open(struct ksmbd_work *work,
		const struct path *path, int flags, __le32 option, int fexist)
{
	struct file *filp;
	int err = 0;
	struct ksmbd_file *fp = NULL;

	filp = dentry_open(path, flags | O_LARGEFILE, current_cred());
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		ksmbd_err("dentry open failed, err %d\n", err);
		return ERR_PTR(err);
	}

	ksmbd_vfs_set_fadvise(filp, option);

	fp = ksmbd_open_fd(work, filp);
	if (IS_ERR(fp)) {
		fput(filp);
		err = PTR_ERR(fp);
		ksmbd_err("id insert failed\n");
		goto err_out;
	}

	if (flags & O_TRUNC) {
		if (fexist)
			smb_break_all_oplock(work, fp);
		err = vfs_truncate((struct path *)path, 0);
		if (err)
			goto err_out;
	}
	return fp;

err_out:
	if (!IS_ERR(fp))
		ksmbd_close_fd(work, fp->volatile_id);
	if (err) {
		fp = ERR_PTR(err);
		ksmbd_err("err : %d\n", err);
	}
	return fp;
}
#else
struct ksmbd_file *ksmbd_vfs_dentry_open(struct ksmbd_work *work,
		const struct path *path, int flags, __le32 option, int fexist)
{
	return NULL;
}
#endif

static int __dir_empty(struct dir_context *ctx, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned int d_type)
{
	struct ksmbd_readdir_data *buf;

	buf = container_of(ctx, struct ksmbd_readdir_data, ctx);
	buf->dirent_count++;

	if (buf->dirent_count > 2)
		return -ENOTEMPTY;
	return 0;
}

/**
 * ksmbd_vfs_empty_dir() - check for empty directory
 * @fp:	ksmbd file pointer
 *
 * Return:	true if directory empty, otherwise false
 */
int ksmbd_vfs_empty_dir(struct ksmbd_file *fp)
{
	int err;
	struct ksmbd_readdir_data readdir_data;

	memset(&readdir_data, 0, sizeof(struct ksmbd_readdir_data));

	set_ctx_actor(&readdir_data.ctx, __dir_empty);
	readdir_data.dirent_count = 0;

	err = ksmbd_vfs_readdir(fp->filp, &readdir_data);
	if (readdir_data.dirent_count > 2)
		err = -ENOTEMPTY;
	else
		err = 0;
	return err;
}

static int __caseless_lookup(struct dir_context *ctx, const char *name,
		int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct ksmbd_readdir_data *buf;

	buf = container_of(ctx, struct ksmbd_readdir_data, ctx);

	if (buf->used != namlen)
		return 0;
	if (!strncasecmp((char *)buf->private, name, namlen)) {
		memcpy((char *)buf->private, name, namlen);
		buf->dirent_count = 1;
		return -EEXIST;
	}
	return 0;
}

/**
 * ksmbd_vfs_lookup_in_dir() - lookup a file in a directory
 * @dirname:	directory name
 * @filename:	filename to lookup
 *
 * Return:	0 on success, otherwise error
 */
static int ksmbd_vfs_lookup_in_dir(char *dirname, char *filename)
{
	struct path dir_path;
	int ret;
	struct file *dfilp;
	int flags = O_RDONLY | O_LARGEFILE;
	int dirnamelen = strlen(dirname);
	struct ksmbd_readdir_data readdir_data = {
		.ctx.actor	= __caseless_lookup,
		.private	= filename,
		.used		= strlen(filename),
	};

	ret = ksmbd_vfs_kern_path(dirname, 0, &dir_path, true);
	if (ret)
		goto error;

	dfilp = dentry_open(&dir_path, flags, current_cred());
	if (IS_ERR(dfilp)) {
		path_put(&dir_path);
		ksmbd_err("cannot open directory %s\n", dirname);
		ret = -EINVAL;
		goto error;
	}

	ret = ksmbd_vfs_readdir(dfilp, &readdir_data);
	if (readdir_data.dirent_count > 0)
		ret = 0;

	fput(dfilp);
	path_put(&dir_path);
error:
	dirname[dirnamelen] = '/';
	return ret;
}

/**
 * ksmbd_vfs_kern_path() - lookup a file and get path info
 * @name:	name of file for lookup
 * @flags:	lookup flags
 * @path:	if lookup succeed, return path info
 * @caseless:	caseless filename lookup
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_kern_path(char *name, unsigned int flags, struct path *path,
		bool caseless)
{
	char *filename = NULL;
	int err;

	err = kern_path(name, flags, path);
	if (!err)
		return err;

	if (caseless) {
		filename = extract_last_component(name);
		if (!filename)
			goto out;

		/* root reached */
		if (strlen(name) == 0)
			goto out;

		err = ksmbd_vfs_lookup_in_dir(name, filename);
		if (err)
			goto out;
		err = kern_path(name, flags, path);
	}

out:
	rollback_path_modification(filename);
	return err;
}

/**
 * ksmbd_vfs_init_kstat() - convert unix stat information to smb stat format
 * @p:          destination buffer
 * @ksmbd_kstat:      ksmbd kstat wrapper
 */
void *ksmbd_vfs_init_kstat(char **p, struct ksmbd_kstat *ksmbd_kstat)
{
	struct file_directory_info *info = (struct file_directory_info *)(*p);
	struct kstat *kstat = ksmbd_kstat->kstat;
	u64 time;

	info->FileIndex = 0;
	info->CreationTime = cpu_to_le64(ksmbd_kstat->create_time);
	time = ksmbd_UnixTimeToNT(kstat->atime);
	info->LastAccessTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(kstat->mtime);
	info->LastWriteTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(kstat->ctime);
	info->ChangeTime = cpu_to_le64(time);

	if (ksmbd_kstat->file_attributes & ATTR_DIRECTORY_LE) {
		info->EndOfFile = 0;
		info->AllocationSize = 0;
	} else {
		info->EndOfFile = cpu_to_le64(kstat->size);
		info->AllocationSize = cpu_to_le64(kstat->blocks << 9);
	}
	info->ExtFileAttributes = ksmbd_kstat->file_attributes;

	return info;
}

int ksmbd_vfs_fill_dentry_attrs(struct ksmbd_work *work, struct dentry *dentry,
		struct ksmbd_kstat *ksmbd_kstat)
{
	u64 time;
	int rc;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	generic_fillattr(&init_user_ns, d_inode(dentry), ksmbd_kstat->kstat);
#else
	generic_fillattr(d_inode(dentry), ksmbd_kstat->kstat);
#endif

	time = ksmbd_UnixTimeToNT(ksmbd_kstat->kstat->ctime);
	ksmbd_kstat->create_time = time;

	/*
	 * set default value for the case that store dos attributes is not yes
	 * or that acl is disable in server's filesystem and the config is yes.
	 */
	if (S_ISDIR(ksmbd_kstat->kstat->mode))
		ksmbd_kstat->file_attributes = ATTR_DIRECTORY_LE;
	else
		ksmbd_kstat->file_attributes = ATTR_ARCHIVE_LE;

	if (test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_STORE_DOS_ATTRS)) {
		struct xattr_dos_attrib da;

		rc = ksmbd_vfs_get_dos_attrib_xattr(dentry, &da);
		if (rc > 0) {
			ksmbd_kstat->file_attributes = cpu_to_le32(da.attr);
			ksmbd_kstat->create_time = da.create_time;
		} else {
			ksmbd_debug(VFS, "fail to load dos attribute.\n");
		}
	}

	return 0;
}

ssize_t ksmbd_vfs_casexattr_len(struct dentry *dentry, char *attr_name,
		int attr_name_len)
{
	char *name, *xattr_list = NULL;
	ssize_t value_len = -ENOENT, xattr_list_len;

	xattr_list_len = ksmbd_vfs_listxattr(dentry, &xattr_list);
	if (xattr_list_len <= 0)
		goto out;

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		ksmbd_debug(VFS, "%s, len %zd\n", name, strlen(name));
		if (strncasecmp(attr_name, name, attr_name_len))
			continue;

		value_len = ksmbd_vfs_xattr_len(dentry, name);
		break;
	}

out:
	ksmbd_vfs_xattr_free(xattr_list);
	return value_len;
}

int ksmbd_vfs_xattr_stream_name(char *stream_name, char **xattr_stream_name,
		size_t *xattr_stream_name_size, int s_type)
{
	int stream_name_size;
	char *xattr_stream_name_buf;
	char *type;
	int type_len;

	if (s_type == DIR_STREAM)
		type = ":$INDEX_ALLOCATION";
	else
		type = ":$DATA";

	type_len = strlen(type);
	stream_name_size = strlen(stream_name);
	*xattr_stream_name_size = stream_name_size + XATTR_NAME_STREAM_LEN + 1;
	xattr_stream_name_buf = kmalloc(*xattr_stream_name_size + type_len,
			GFP_KERNEL);
	if (!xattr_stream_name_buf)
		return -ENOMEM;

	memcpy(xattr_stream_name_buf,
		XATTR_NAME_STREAM,
		XATTR_NAME_STREAM_LEN);

	if (stream_name_size) {
		memcpy(&xattr_stream_name_buf[XATTR_NAME_STREAM_LEN],
			stream_name,
			stream_name_size);
	}
	memcpy(&xattr_stream_name_buf[*xattr_stream_name_size - 1], type, type_len);
		*xattr_stream_name_size += type_len;

	xattr_stream_name_buf[*xattr_stream_name_size - 1] = '\0';
	*xattr_stream_name = xattr_stream_name_buf;

	return 0;
}

static int ksmbd_vfs_copy_file_range(struct file *file_in, loff_t pos_in,
		struct file *file_out, loff_t pos_out, size_t len)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	ret = vfs_copy_file_range(file_in, pos_in, file_out, pos_out, len, 0);
	/* do splice for the copy between different file systems */
	if (ret != -EXDEV)
		return ret;
#endif

	if (S_ISDIR(inode_in->i_mode) || S_ISDIR(inode_out->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode_in->i_mode) || !S_ISREG(inode_out->i_mode))
		return -EINVAL;

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE))
		return -EBADF;

	if (len == 0)
		return 0;

	file_start_write(file_out);

	/*
	 * skip the verification of the range of data. it will be done
	 * in do_splice_direct
	 */
	ret = do_splice_direct(file_in, &pos_in, file_out, &pos_out,
			len > MAX_RW_COUNT ? MAX_RW_COUNT : len, 0);
	if (ret > 0) {
		fsnotify_access(file_in);
		add_rchar(current, ret);
		fsnotify_modify(file_out);
		add_wchar(current, ret);
	}

	inc_syscr(current);
	inc_syscw(current);

	file_end_write(file_out);
	return ret;
}

int ksmbd_vfs_copy_file_ranges(struct ksmbd_work *work,
		struct ksmbd_file *src_fp, struct ksmbd_file *dst_fp,
		struct srv_copychunk *chunks, unsigned int chunk_count,
		unsigned int *chunk_count_written,
		unsigned int *chunk_size_written, loff_t *total_size_written)
{
	unsigned int i;
	loff_t src_off, dst_off, src_file_size;
	size_t len;
	int ret;

	*chunk_count_written = 0;
	*chunk_size_written = 0;
	*total_size_written = 0;

	if (!(src_fp->daccess & (FILE_READ_DATA_LE | FILE_EXECUTE_LE))) {
		ksmbd_err("no right to read(%s)\n", FP_FILENAME(src_fp));
		return -EACCES;
	}
	if (!(dst_fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE))) {
		ksmbd_err("no right to write(%s)\n", FP_FILENAME(dst_fp));
		return -EACCES;
	}

	if (ksmbd_stream_fd(src_fp) || ksmbd_stream_fd(dst_fp))
		return -EBADF;

	smb_break_all_levII_oplock(work, dst_fp, 1);

	if (!work->tcon->posix_extensions) {
		for (i = 0; i < chunk_count; i++) {
			src_off = le64_to_cpu(chunks[i].SourceOffset);
			dst_off = le64_to_cpu(chunks[i].TargetOffset);
			len = le32_to_cpu(chunks[i].Length);

			if (check_lock_range(src_fp->filp, src_off,
					     src_off + len - 1, READ))
				return -EAGAIN;
			if (check_lock_range(dst_fp->filp, dst_off,
					     dst_off + len - 1, WRITE))
				return -EAGAIN;
		}
	}

	src_file_size = i_size_read(file_inode(src_fp->filp));

	for (i = 0; i < chunk_count; i++) {
		src_off = le64_to_cpu(chunks[i].SourceOffset);
		dst_off = le64_to_cpu(chunks[i].TargetOffset);
		len = le32_to_cpu(chunks[i].Length);

		if (src_off + len > src_file_size)
			return -E2BIG;

		ret = ksmbd_vfs_copy_file_range(src_fp->filp, src_off,
				dst_fp->filp, dst_off, len);
		if (ret < 0)
			return ret;

		*chunk_count_written += 1;
		*total_size_written += ret;
	}
	return 0;
}

int ksmbd_vfs_posix_lock_wait(struct file_lock *flock)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	return wait_event_interruptible(flock->fl_wait, !flock->fl_next);
#else
	return wait_event_interruptible(flock->fl_wait, !flock->fl_blocker);
#endif
}

int ksmbd_vfs_posix_lock_wait_timeout(struct file_lock *flock, long timeout)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	return wait_event_interruptible_timeout(flock->fl_wait,
						!flock->fl_next,
						timeout);
#else
	return wait_event_interruptible_timeout(flock->fl_wait,
						!flock->fl_blocker,
						timeout);
#endif
}

void ksmbd_vfs_posix_lock_unblock(struct file_lock *flock)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	posix_unblock_lock(flock);
#else
	locks_delete_block(flock);
#endif
}

int ksmbd_vfs_set_init_posix_acl(struct inode *inode)
{
	struct posix_acl_state acl_state;
	struct posix_acl *acls;
	int rc;

	ksmbd_debug(SMB, "Set posix acls\n");
	rc = init_acl_state(&acl_state, 1);
	if (rc)
		return rc;

	/* Set default owner group */
	acl_state.owner.allow = (inode->i_mode & 0700) >> 6;
	acl_state.group.allow = (inode->i_mode & 0070) >> 3;
	acl_state.other.allow = inode->i_mode & 0007;
	acl_state.users->aces[acl_state.users->n].uid = inode->i_uid;
	acl_state.users->aces[acl_state.users->n++].perms.allow =
		acl_state.owner.allow;
	acl_state.groups->aces[acl_state.groups->n].gid = inode->i_gid;
	acl_state.groups->aces[acl_state.groups->n++].perms.allow =
		acl_state.group.allow;
	acl_state.mask.allow = 0x07;

	acls = ksmbd_vfs_posix_acl_alloc(6, GFP_KERNEL);
	if (!acls) {
		free_acl_state(&acl_state);
		return -ENOMEM;
	}
	posix_state_to_acl(&acl_state, acls->a_entries);
	rc = ksmbd_vfs_set_posix_acl(inode, ACL_TYPE_ACCESS, acls);
	if (rc < 0)
		ksmbd_debug(SMB, "Set posix acl(ACL_TYPE_ACCESS) failed, rc : %d\n",
				rc);
	else if (S_ISDIR(inode->i_mode)) {
		posix_state_to_acl(&acl_state, acls->a_entries);
		rc = ksmbd_vfs_set_posix_acl(inode, ACL_TYPE_DEFAULT, acls);
		if (rc < 0)
			ksmbd_debug(SMB, "Set posix acl(ACL_TYPE_DEFAULT) failed, rc : %d\n",
					rc);
	}
	free_acl_state(&acl_state);
	posix_acl_release(acls);
	return rc;
}

int ksmbd_vfs_inherit_posix_acl(struct inode *inode, struct inode *parent_inode)
{
	struct posix_acl *acls;
	struct posix_acl_entry *pace;
	int rc, i;

	acls = ksmbd_vfs_get_acl(parent_inode, ACL_TYPE_DEFAULT);
	if (!acls)
		return -ENOENT;
	pace = acls->a_entries;

	for (i = 0; i < acls->a_count; i++, pace++) {
		if (pace->e_tag == ACL_MASK) {
			pace->e_perm = 0x07;
			break;
		}
	}

	rc = ksmbd_vfs_set_posix_acl(inode, ACL_TYPE_ACCESS, acls);
	if (rc < 0)
		ksmbd_debug(SMB, "Set posix acl(ACL_TYPE_ACCESS) failed, rc : %d\n",
				rc);
	if (S_ISDIR(inode->i_mode)) {
		rc = ksmbd_vfs_set_posix_acl(inode, ACL_TYPE_DEFAULT, acls);
		if (rc < 0)
			ksmbd_debug(SMB, "Set posix acl(ACL_TYPE_DEFAULT) failed, rc : %d\n",
					rc);
	}
	posix_acl_release(acls);
	return rc;
}
