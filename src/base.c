/*
 * Copyright © 2022 omame <me@omame.xyz>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>

#include "omamefs_spec.h"

uint8_t *build_test_fs();

uint8_t *test_fs_data;

static void *omamefs_test_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg)
{
	(void) conn;
	cfg->kernel_cache = 1;
	test_fs_data = build_test_fs();
	return NULL;
}

static int hello_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;

	memset(stbuf, 0, sizeof(struct stat));
	/* if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path+1, options.filename) == 0) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(options.contents);
	} else
		res = -ENOENT; */

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}
	
	struct omamefs_header *header = (struct omamefs_header *) test_fs_data;
	struct omamefs_file_header *next_file = (struct omamefs_file_header *) &test_fs_data[(uint64_t) header->first_file];
	while (true) {
		if (strncmp(path + 1, &test_fs_data[(uint64_t) next_file->name], next_file->name_length) == 0) {
			if (next_file->is_folder) {
				stbuf->st_mode = S_IFDIR | next_file->permissions;
			} else {
				stbuf->st_mode = S_IFREG | next_file->permissions;
				stbuf->st_size = next_file->size;
			}
			stbuf->st_uid = next_file->uid;
			stbuf->st_gid = next_file->gid;
			return 0;
		}
		if (next_file->next_file == NULL) break;
		next_file = (struct omamefs_file_header *) &test_fs_data[(uint64_t) next_file->next_file];
	}

	return -ENOENT;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	// filler(buf, options.filename, NULL, 0, 0);

	struct omamefs_header *header = (struct omamefs_header *) test_fs_data;
	struct omamefs_file_header *next_file = (struct omamefs_file_header *) &test_fs_data[(uint64_t) header->first_file];
	while (true) {
		char *filename = malloc(next_file->name_length + 1);
		memset(filename, '\0', next_file->name_length + 1);
		memcpy(filename, &test_fs_data[(uint64_t) next_file->name], next_file->name_length);
		filler(buf, filename, NULL, 0, 0);
		if (next_file->next_file == NULL) break;
		next_file = (struct omamefs_file_header *) &test_fs_data[(uint64_t) next_file->next_file];
	}

	return 0;
}

static int hello_open(const char *path, struct fuse_file_info *fi)
{
	/* if (strcmp(path+1, options.filename) != 0)
		return -ENOENT; */

	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	struct omamefs_header *header = (struct omamefs_header *) test_fs_data;
	struct omamefs_file_header *next_file = (struct omamefs_file_header *) &test_fs_data[(uint64_t) header->first_file];
	while (true) {
		if (strncmp(path + 1, &test_fs_data[(uint64_t) next_file->name], next_file->name_length) == 0) {
			if (next_file->is_folder) {
				return -ENOENT;
			} else {
				return 0;
			}
		}
		if (next_file->next_file == NULL) break;
		next_file = (struct omamefs_file_header *) &test_fs_data[(uint64_t) next_file->next_file];
	}

	return -ENOENT;
}

static int hello_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;
	/* size_t len;
	(void) fi;
	if(strcmp(path+1, options.filename) != 0)
		return -ENOENT;

	len = strlen(options.contents);
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, options.contents + offset, size);
	} else
		size = 0;

	return size; */
	
	struct omamefs_header *header = (struct omamefs_header *) test_fs_data;
	struct omamefs_file_header *next_file = (struct omamefs_file_header *) &test_fs_data[(uint64_t) header->first_file];
	while (true) {
		if (strncmp(path + 1, &test_fs_data[(uint64_t) next_file->name], next_file->name_length) == 0) {
			if (next_file->is_folder) {
				return -ENOENT;
			} else {
				size_t len = (size_t) next_file->size;
				if (offset < len) {
					if (offset + size > len)
						size = len - offset;
					memcpy(buf, &test_fs_data[(uint64_t) (next_file->data) + offset], size);
				} else
					size = 0;
				
				return size;
			}
		}
		if (next_file->next_file == NULL) break;
		next_file = (struct omamefs_file_header *) &test_fs_data[(uint64_t) next_file->next_file];
	}

	return -ENOENT;
}

static const struct fuse_operations omamefs_test_oper = {
	.init           = omamefs_test_init,
	.getattr	= hello_getattr,
	.readdir	= hello_readdir,
	.open		= hello_open,
	.read		= hello_read,
};

uint8_t *build_test_fs() {
	uint8_t *data = malloc(0x100);
    memset(data, '\0', 0x100);

	char *name = "file.txt";
	char *contents = "hello, fs!";

	char *label = "test fs";

    struct omamefs_header header = {
		.magic = "omame",
		.extended_attributes = (struct omamefs_extended_attributes *)(sizeof(struct omamefs_header)),
		.first_file = (struct omamefs_file_header *)((uint64_t) (header.extended_attributes) + sizeof(struct omamefs_extended_attributes) + strlen(label) + 1),
		.next_file = (void *)((uint64_t) (header.first_file) + sizeof(struct omamefs_file_header) + strlen(name) + strlen(contents) + 1),
	};

	struct omamefs_extended_attributes attr = {
		.label_length = strlen(label),
		.label = (char *)((uint64_t) (header.extended_attributes) + sizeof(struct omamefs_extended_attributes))
	};

	struct omamefs_file_header file = {
		.name_length = strlen(name),
		.name = (char *)((uint64_t) (header.first_file) + sizeof(struct omamefs_file_header)),
		.is_folder = false,
		.size = strlen(contents),
		.permissions = 0644,
		.uid = 1000,
		.gid = 1000,
		.data = (char *)((uint64_t) (header.first_file) + sizeof(struct omamefs_file_header) + strlen(name)),
	};

    memcpy(data, &header, sizeof(struct omamefs_header));
	memcpy(&data[(uint64_t) header.extended_attributes], &attr, sizeof(struct omamefs_extended_attributes));
	memcpy(&data[(uint64_t) attr.label], label, strlen(label) * sizeof(char));
	memcpy(&data[(uint64_t) header.first_file], &file, sizeof(struct omamefs_file_header));
	memcpy(&data[(uint64_t) file.name], name, strlen(name) * sizeof(char));
	memcpy(&data[(uint64_t) file.data], contents, strlen(contents) * sizeof(char));

	return data;
}
