/*
 * Copyright © 2022 omame <me@omame.xyz>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef OMAMEFS_SPEC_H
#define OMAMEFS_SPEC_H

#ifdef __cplusplus__
extern C {
#endif


#include <stdbool.h>
#include <stddef.h>

struct omamefs_file_header;

struct __attribute__((packed)) omamefs_file_header {
    uint8_t name_length;
    char *name;
    bool is_folder;
    uint64_t size;
    uint16_t permissions;
    uint16_t uid;
    uint16_t gid;
    uint8_t *data; // in case of folder, data will contain a pointer to a file header
    struct omamefs_file_header *next_file;
};

struct __attribute__((packed)) omamefs_extended_attributes {
    uint8_t label_length;
    char *label;
};

struct __attribute__((packed)) omamefs_header {
    char magic[5]; // should always be "omame"

    struct omamefs_extended_attributes *extended_attributes;
    struct omamefs_file_header *first_file;
    void *next_file;
};


#ifdef __cplusplus__
}
#endif

#endif // OMAMEFS_SPEC_H
