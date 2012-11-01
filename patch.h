/* Patch Header 

  Copyright (c) 2012, Nikolaj Schlej. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#ifndef __PATCH_H__
#define __PATCH_H__

#include "Common/UefiBaseTypes.h"

#define UUID_LENGTH 16

// Data structures 
// Common UEFI module header 
#pragma pack(push, 1)
typedef struct {
    UINT8 guid[UUID_LENGTH];
    UINT8 header_checksum;
    UINT8 data_checksum;
    UINT8 type;
    UINT8 atributes;
    UINT8 size[3];
    UINT8 state;
} module_header;

// Compressed section type for nested module
#define SECTION_COMPRESSED  0x01
// GUID-defined section for Dell PowerManagement2.efi module
#define SECTION_GUID_DEFINED 0x02
// DXE driver section type for PowerManagement module 
#define SECTION_DXE_DEPEX   0x13
// Common section header 
typedef struct {
    UINT8 size[3];
    UINT8 type;
} common_section_header;

// GUID-defined section header
typedef struct {    
    UINT8 size[3];
    UINT8 type;
    UINT8 guid[16];
    UINT16 data_offset;
    UINT16 attributes;
} guid_section_header;

// Uncompressed data type 
#define COMPRESSION_NONE 0x00
// Tiano compressed data type 
#define COMPRESSION_TIANO 0x01
// LZMA compressed data type 
#define COMPRESSION_LZMA  0x02
// Compressed section header 
typedef struct {
    UINT8 size[3];
    UINT8 type;
    UINT32 decompressed_size;
    UINT8 compression_type;
} compressed_section_header;
#pragma pack(pop)

// Error codes 
#define ERR_PATCHED                         0x00
#define ERR_INVALID_ARGUMENT                0x01
#define ERR_UNKNOWN_MODULE                  0x02
#define ERR_UNKNOWN_COMPRESSION_TYPE        0x03
#define ERR_TIANO_DECOMPRESSION_FAILED      0x04
#define ERR_LZMA_DECOMPRESSION_FAILED       0x05
#define ERR_PATCH_STRING_NOT_FOUND          0x06
#define ERR_TIANO_COMPRESSION_FAILED        0x07
#define ERR_LZMA_COMPRESSION_FAILED         0x08
#define ERR_PATCHED_MODULE_INSERTION_FAILED 0x09
#define ERR_MODULE_NOT_FOUND                0x0A

// Patches module 
UINT8 patch_bios(UINT8* bios, UINT32 size);

#endif // __PATCH_H__ 
