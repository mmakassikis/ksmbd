// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/xattr.h>
#include <linux/fs.h>

#include "misc.h"
#include "smb_common.h"
#include "connection.h"
#include "vfs.h"

#include "mgmt/share_config.h"

/**
 * match_pattern() - compare a string with a pattern which might include
 * wildcard '*' and '?'
 * TODO : implement consideration about DOS_DOT, DOS_QM and DOS_STAR
 *
 * @string:	string to compare with a pattern
 * @len:	string length
 * @pattern:	pattern string which might include wildcard '*' and '?'
 *
 * Return:	0 if pattern matched with the string, otherwise non zero value
 */
int match_pattern(const char *str, size_t len, const char *pattern)
{
	const char *s = str;
	const char *p = pattern;
	bool star = false;

	while (*s && len) {
		switch (*p) {
		case '?':
			s++;
			len--;
			p++;
			break;
		case '*':
			star = true;
			str = s;
			if (!*++p)
				return true;
			pattern = p;
			break;
		default:
			if (tolower(*s) == tolower(*p)) {
				s++;
				len--;
				p++;
			} else {
				if (!star)
					return false;
				str++;
				s = str;
				p = pattern;
			}
			break;
		}
	}

	if (*p == '*')
		++p;
	return !*p;
}

/*
 * is_char_allowed() - check for valid character
 * @ch:		input character to be checked
 *
 * Return:	1 if char is allowed, otherwise 0
 */
static inline int is_char_allowed(char ch)
{
	/* check for control chars, wildcards etc. */
	if (!(ch & 0x80) &&
	    (ch <= 0x1f ||
	     ch == '?' || ch == '"' || ch == '<' ||
	     ch == '>' || ch == '|' || ch == '*'))
		return 0;

	return 1;
}

int ksmbd_validate_filename(char *filename)
{
	while (*filename) {
		char c = *filename;

		filename++;
		if (!is_char_allowed(c)) {
			ksmbd_debug(VFS, "File name validation failed: 0x%x\n", c);
			return -ENOENT;
		}
	}

	return 0;
}

static int ksmbd_validate_stream_name(char *stream_name)
{
	while (*stream_name) {
		char c = *stream_name;

		stream_name++;
		if (c == '/' || c == ':' || c == '\\') {
			ksmbd_err("Stream name validation failed: %c\n", c);
			return -ENOENT;
		}
	}

	return 0;
}

int parse_stream_name(char *filename, char **stream_name, int *s_type)
{
	char *stream_type;
	char *s_name;
	int rc = 0;

	s_name = filename;
	filename = strsep(&s_name, ":");
	ksmbd_debug(SMB, "filename : %s, streams : %s\n", filename, s_name);
	if (strchr(s_name, ':')) {
		stream_type = s_name;
		s_name = strsep(&stream_type, ":");

		rc = ksmbd_validate_stream_name(s_name);
		if (rc < 0) {
			rc = -ENOENT;
			goto out;
		}

		ksmbd_debug(SMB, "stream name : %s, stream type : %s\n", s_name,
				stream_type);
		if (!strncasecmp("$data", stream_type, 5))
			*s_type = DATA_STREAM;
		else if (!strncasecmp("$index_allocation", stream_type, 17))
			*s_type = DIR_STREAM;
		else
			rc = -ENOENT;
	}

	*stream_name = s_name;
out:
	return rc;
}

/**
 * convert_to_nt_pathname() - extract and return windows path string
 *      whose share directory prefix was removed from file path
 * @filename : unix filename
 * @sharepath: share path string
 *
 * Return : windows path string or error
 */

char *convert_to_nt_pathname(char *filename, char *sharepath)
{
	char *ab_pathname;
	int len, name_len;

	name_len = strlen(filename);
	ab_pathname = kmalloc(name_len, GFP_KERNEL);
	if (!ab_pathname)
		return NULL;

	ab_pathname[0] = '\\';
	ab_pathname[1] = '\0';

	len = strlen(sharepath);
	if (!strncmp(filename, sharepath, len) && name_len != len) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		strncpy(ab_pathname, &filename[len], name_len);
#else
		strscpy(ab_pathname, &filename[len], name_len);
#endif
		ksmbd_conv_path_to_windows(ab_pathname);
	}

	return ab_pathname;
}

int get_nlink(struct kstat *st)
{
	int nlink;

	nlink = st->nlink;
	if (S_ISDIR(st->mode))
		nlink--;

	return nlink;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
static void strreplace(char *s, char old, char new)
{
	for (; *s; ++s)
		if (*s == old)
			*s = new;
}
#endif

void ksmbd_conv_path_to_unix(char *path)
{
	strreplace(path, '\\', '/');
}

void ksmbd_strip_last_slash(char *path)
{
	int len = strlen(path);

	while (len && path[len - 1] == '/') {
		path[len - 1] = '\0';
		len--;
	}
}

void ksmbd_conv_path_to_windows(char *path)
{
	strreplace(path, '/', '\\');
}

/**
 * ksmbd_extract_sharename() - get share name from tree connect request
 * @treename:	buffer containing tree name and share name
 *
 * Return:      share name on success, otherwise error
 */
char *ksmbd_extract_sharename(char *treename)
{
	char *name = treename;
	char *dst;
	char *pos = strrchr(name, '\\');

	if (pos)
		name = (pos + 1);

	/* caller has to free the memory */
	dst = kstrdup(name, GFP_KERNEL);
	if (!dst)
		return ERR_PTR(-ENOMEM);
	return dst;
}

/**
 * convert_to_unix_name() - convert windows name to unix format
 * @path:	name to be converted
 * @tid:	tree id of mathing share
 *
 * Return:	converted name on success, otherwise NULL
 */
char *convert_to_unix_name(struct ksmbd_share_config *share, char *name)
{
	int no_slash = 0, name_len, path_len;
	char *new_name;

	if (name[0] == '/')
		name++;

	path_len = share->path_sz;
	name_len = strlen(name);
	new_name = kmalloc(path_len + name_len + 2, GFP_KERNEL);
	if (!new_name)
		return new_name;

	memcpy(new_name, share->path, path_len);
	if (new_name[path_len - 1] != '/') {
		new_name[path_len] = '/';
		no_slash = 1;
	}

	memcpy(new_name + path_len + no_slash, name, name_len);
	path_len += name_len + no_slash;
	new_name[path_len] = 0x00;
	return new_name;
}

char *ksmbd_convert_dir_info_name(struct ksmbd_dir_info *d_info,
		const struct nls_table *local_nls, int *conv_len)
{
	char *conv;
	int  sz = min(4 * d_info->name_len, PATH_MAX);

	if (!sz)
		return NULL;

	conv = kmalloc(sz, GFP_KERNEL);
	if (!conv)
		return NULL;

	/* XXX */
	*conv_len = smbConvertToUTF16((__le16 *)conv,
					d_info->name,
					d_info->name_len,
					local_nls,
					0);
	*conv_len *= 2;

	/* We allocate buffer twice bigger than needed. */
	conv[*conv_len] = 0x00;
	conv[*conv_len + 1] = 0x00;
	return conv;
}
