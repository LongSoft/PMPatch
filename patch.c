/* Patch Implementation

  Copyright (c) 2012, Nikolaj Schlej. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#include <stdio.h>
#include <stdlib.h>

#include "Tiano/TianoCompress.h"
#include "Tiano/TianoDecompress.h"
#include "LZMA/LzmaCompress.h"
#include "LZMA/LzmaDecompress.h"

#include "patch.h"

// UUIDs 
CONST UINT8 NESTED_UUID[] = 
{0x2F,0x7C,0x71,0xAE,0x42,0x1A,0x2B,0x4F,0x88,0x61,0x78,0xB7,0x9C,0xA0,0x7E,0x07};
CONST UINT8 PHOENIX_NESTED_UUID[] =
{0x18,0x88,0x53,0x4A,0xE0,0x5A,0xB2,0x4E,0xB2,0xEB,0x48,0x8B,0x23,0x65,0x70,0x22};
CONST UINT8 POWERMANAGEMENT_UUID[] =
{0x70,0x39,0x78,0x8C,0x2A,0xF0,0x4D,0x4A,0xAF,0x09,0x87,0x97,0xA5,0x1E,0xEC,0x8D};
CONST UINT8 POWERMANAGEMENT2_UUID[] =
{0x4C,0x1B,0x73,0xF7,0xA2,0x58,0xF4,0x4D,0x89,0x80,0x56,0x45,0xD3,0x9E,0xCE,0x58};
CONST UINT8 CPUPEI_UUID[] = 
{0xA9,0xAF,0xB5,0x2B,0x33,0xFF,0x7B,0x41,0x84,0x97,0xCB,0x77,0x3C,0x2B,0x93,0xBF};
CONST UINT8 PLATFORMSETUPADVANCED_UUID[] =
{0xC4,0x94,0xEF,0xCF,0x67,0x41,0x6A,0x46,0x88,0x93,0x87,0x79,0x45,0x9D,0xFA,0x86};
CONST UINT8 DELL_RAW_FILE_GUID[] =
{0x7F,0x36,0x3E,0xF3,0xD2,0x41,0x01,0x42,0x9C,0xB7,0xAF,0xA6,0x3D,0xCC,0xEE,0xC9};

// PowerManagement patch 
CONST UINT8 POWERMANAGEMENT_PATCH_PATTERN[] =
{0x75,0x08,0x0F,0xBA,0xE8,0x0F,0x89,0x44,0x24,0x30};
CONST UINT8 POWERMANAGEMENT_PATCHED_PATTERNS[][13] =  {
    {0xEB,0x08,0x0F,0xBA,0xE8,0x0F,0x89,0x44,0x24,0x30},
    {0xEB,0x08,0x0F,0xBA,0xE8,0x0F,0x90,0x90,0x90,0x90},
    {0xEB,0x08,0x90,0x90,0x90,0x90,0x89,0x44,0x24,0x30},
    {0xEB,0x08,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90},
    {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90},
};
CONST UINT8 PATCHED_PATTERNS_COUNT = 
    sizeof(POWERMANAGEMENT_PATCHED_PATTERNS)/sizeof(POWERMANAGEMENT_PATCHED_PATTERNS[0]);

// CpuPei patch 
CONST UINT8 CPUPEI_PATCH_PATTERN[] =      
{0x80,0x00,0x18,0xEB,0x05,0x0D,0x00,0x80};
CONST UINT8 CPUPEI_PATCHED_PATTERN[] =    
{0x00,0x00,0x18,0xEB,0x05,0x0D,0x00,0x00};

// Phoenix PlatformSetupAdvancedDxe patch to unclock additional BIOS settings
CONST UINT8 PLATFORMSETUPADVANCED_PATCH_PATTERN[] =
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x45,0x0A};
CONST UINT8 PLATFORMSETUPADVANCED_PATCHED_PATTERN[] =
{0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x45,0x0A};
CONST UINT8 PLATFORMSETUPADVANCED_UNICODE_PATCH_PATTERN[] =
{0x00,0x14,0x42,0x00,0x65,0x00,0x6C,0x00,0x6F,0x00,0x77,0x00,0x20,0x00,0x69,0x00,
 0x73,0x00,0x20,0x00,0x72,0x00,0x65,0x00,0x73,0x00,0x65,0x00,0x72,0x00,0x76,0x00,
 0x65,0x00,0x64,0x00,0x20,0x00,0x66,0x00,0x6F,0x00,0x72,0x00,0x20,0x00,0x52,0x00,
 0x44,0x00,0x2C,0x00,0x20,0x00,0x6E,0x00,0x6F,0x00,0x74,0x00,0x20,0x00,0x44,0x00,
 0x45,0x00,0x4C,0x00,0x4C,0x00,0x4F,0x00,0x49,0x00,0x4C,0x00,0x20,0x00,0x72,0x00,
 0x65,0x00,0x71,0x00,0x75,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x2E,0x00,0x00,0x00};
CONST UINT8 PLATFORMSETUPADVANCED_UNICODE_PATCHED_PATTERN[] =
{0x00,0x14,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,
 0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,
 0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,
 0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,
 0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,
 0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x00,0x00};

// Implementation of GNU memmem function using Boyer-Moore-Horspool algorithm 
UINT8* find_pattern(UINT8* string, UINT32 slen, CONST UINT8* pattern, UINT32 plen)
{
    UINT32 scan = 0;
    UINT32 bad_char_skip[256];
    UINT32 last;

    if (plen == 0 || !string || !pattern)
        return NULL;

    for (scan = 0; scan <= 255; scan++)
        bad_char_skip[scan] = plen;

    last = plen - 1;

    for (scan = 0; scan < last; scan++)
        bad_char_skip[pattern[scan]] = last - scan;

    while (slen >= plen)
    {
        for (scan = last; string[scan] == pattern[scan]; scan--)
            if (scan == 0)
                return string;

        slen     -= bad_char_skip[string[last]];
        string   += bad_char_skip[string[last]];
    }

    return NULL;
}

UINT8 calculate_checksum(UINT8* data, UINT32 length)
{
    UINT8 counter = 0;
    while(length--)
        counter += data[length];
    return ~counter + 1;
}

VOID int2size(UINT32 size, UINT8* module_size)
{
    module_size[2] = (UINT8) ((size) >> 16);
    module_size[1] = (UINT8) ((size) >>  8);
    module_size[0] = (UINT8) ((size)      );
}

UINT32 size2int(UINT8* module_size)
{
    return (module_size[2] << 16) + 
        (module_size[1] << 8)  + 
        module_size[0];
}

UINT8 correct_checksums(UINT8* module)
{
    UINT8* string;
    module_header *header;

    if(!module)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;

    // Calculating new module checksums 
    header->header_checksum = 0;
    header->data_checksum = 0;
    header->header_checksum = calculate_checksum(module, sizeof(module_header) - 1);
    header->data_checksum = calculate_checksum(module + sizeof(module_header), size2int(header->size) - sizeof(module_header));

    return ERR_PATCHED;
}

UINT8 patch_powermanagement_module(UINT8* module)
{
    module_header *header;
    common_section_header *common_header;
    compressed_section_header *compressed_header;
    UINT8* data;
    UINT32 data_size;
    UINT8* compressed;
    UINT32 compressed_size;
    UINT8* decompressed;
    UINT32 decompressed_size;
    UINT8* scratch;
    UINT32 scratch_size;
    UINT8* string;
    UINT8 current_patch;
    BOOLEAN is_patched;
    INT32 module_size_change;
    UINT32 grow;
    UINT8 level;

    if(!module)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;
    data = module + sizeof(module_header);

    
    common_header = (common_section_header*) data;
    // Skipping DXE dependancy section in the beginning of PowerManagement module 
    if (common_header->type == SECTION_DXE_DEPEX)
        data += size2int(common_header->size);
    else 
        return ERR_UNKNOWN_MODULE;

    compressed_header = (compressed_section_header*) data;
    data += sizeof(compressed_section_header);
    data_size = size2int(compressed_header->size) - sizeof(compressed_section_header);

    // Decompressing module data 
    switch (compressed_header->compression_type)
    {
    case COMPRESSION_TIANO:
        if (TianoGetInfo(data, data_size, &decompressed_size, &scratch_size) != EFI_SUCCESS
            ||  decompressed_size != compressed_header->decompressed_size)
            return ERR_TIANO_DECOMPRESSION_FAILED;

        decompressed = (UINT8*)malloc(decompressed_size);
        scratch = (UINT8*)malloc(scratch_size);

        if (TianoDecompress(data, data_size, decompressed, decompressed_size, scratch, scratch_size) != EFI_SUCCESS)
            return ERR_TIANO_DECOMPRESSION_FAILED;
        free(scratch);
        break;
    case COMPRESSION_LZMA:
        if (LzmaGetInfo(data, data_size, &decompressed_size, &scratch_size) != EFI_SUCCESS
            ||  decompressed_size != compressed_header->decompressed_size)
            return ERR_LZMA_DECOMPRESSION_FAILED;

        decompressed = (UINT8*)malloc(decompressed_size);
        scratch = (UINT8*)malloc(scratch_size);

        if (LzmaDecompress(data, data_size, decompressed, scratch) != EFI_SUCCESS)
            return ERR_LZMA_DECOMPRESSION_FAILED;
        free(scratch);
        break;
    case COMPRESSION_NONE:
        decompressed = data;
        decompressed_size = data_size;
        break;
    default:
        return ERR_UNKNOWN_COMPRESSION_TYPE;
    }

    // Searching for patch string 
    string = find_pattern(decompressed, decompressed_size, POWERMANAGEMENT_PATCH_PATTERN, sizeof(POWERMANAGEMENT_PATCH_PATTERN));
    if (!string)
        return ERR_PATCH_STRING_NOT_FOUND;

    // Trying all patched strings 
    is_patched = FALSE;
    for(current_patch = 0; current_patch < PATCHED_PATTERNS_COUNT; current_patch++)
    {
        // Patching founded string with current patch 
        memcpy(string, POWERMANAGEMENT_PATCHED_PATTERNS[current_patch], sizeof(POWERMANAGEMENT_PATCH_PATTERN));

        // Compressing patched module 
        switch(compressed_header->compression_type)
        {
        case COMPRESSION_TIANO:
            compressed_size = 0;
            if (TianoCompress(decompressed, decompressed_size, compressed, &compressed_size) != EFI_BUFFER_TOO_SMALL)
                return ERR_TIANO_COMPRESSION_FAILED;
            compressed = (UINT8*)malloc(compressed_size);
            if (TianoCompress(decompressed, decompressed_size, compressed, &compressed_size) != EFI_SUCCESS)
                return ERR_TIANO_COMPRESSION_FAILED;
            break;
        case COMPRESSION_LZMA:
            for(level = 5; level < 10; level++)
            {
                compressed_size = 0;
                if(LzmaCompress(decompressed, decompressed_size, compressed, &compressed_size, level) != EFI_BUFFER_TOO_SMALL)
                    return ERR_LZMA_COMPRESSION_FAILED;
                compressed = (UINT8*)malloc(compressed_size);
                if (LzmaCompress(decompressed, decompressed_size, compressed, &compressed_size, level) != EFI_SUCCESS)
                    return ERR_TIANO_COMPRESSION_FAILED;
                grow = data_size > compressed_size ? data_size - compressed_size : compressed_size - data_size;
                if(grow > 4)
                    free(compressed);
                else
                    break;
            }
            break;
        case COMPRESSION_NONE:
            compressed = decompressed;
            compressed_size = decompressed_size;
            break;
        default:
            return ERR_UNKNOWN_COMPRESSION_TYPE;
        }

        // Checking compressed data size 
        if(data_size < compressed_size)
        {
            UINT32 grow = compressed_size - data_size;
            UINT8* end = data + data_size;
            BOOLEAN can_insert = TRUE;
            while(grow--)
                if(*end-- != 0xFF)
                {
                    can_insert = FALSE;
                    break;
                }
                if(!can_insert)
                    continue;
        }
        else if (data_size > compressed_size)
        {
            UINT8 freespace_length;
            UINT32 grow = data_size - compressed_size;
            UINT8* end = data + data_size;
            for(freespace_length = 0; *end++ == 0xFF; freespace_length++);
            if(grow + freespace_length >= 8)
                continue;
        }

        is_patched = TRUE;
        break;
    }

    if (!is_patched)
        return ERR_PATCHED_MODULE_INSERTION_FAILED;

    // Writing new module 
    if(data_size > compressed_size)
        memset(data + compressed_size, 0xFF, data_size - compressed_size);
    if(compressed_header->compression_type != COMPRESSION_NONE)
    {
        memcpy(data, compressed, compressed_size);
        // Writing new compressed section size 
        int2size(compressed_size + sizeof(compressed_section_header), compressed_header->size);
        // Writing new module size 
        module_size_change = compressed_size - data_size; 
        int2size(size2int(header->size) + module_size_change, header->size);
    }

    // Correcting checksums
    return correct_checksums(module);
}

UINT8 patch_powermanagement2_module(UINT8* module)
{
    UINT8* string;
    UINT8* data;
    module_header *header;
    guid_section_header *guid_header;

    if(!module)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;
    data = module + sizeof(module_header);

    guid_header = (guid_section_header*) data;
    // Skipping GUID definition section in the beginning of PowerManagement2.efi module 
    if (guid_header->type == SECTION_GUID_DEFINED)
        data += guid_header->data_offset;
    else 
        return ERR_UNKNOWN_MODULE;

    // Searching for patch string 
    string = find_pattern(data, size2int(guid_header->size), POWERMANAGEMENT_PATCH_PATTERN, sizeof(POWERMANAGEMENT_PATCH_PATTERN));
    if(!string)
        return ERR_PATCH_STRING_NOT_FOUND;

    // Patching
    memcpy(string, POWERMANAGEMENT_PATCHED_PATTERNS[0], sizeof(POWERMANAGEMENT_PATCH_PATTERN));

    // Correcting checksums
    return correct_checksums(module);  
}

UINT8 patch_platformsetupadvanced_module(UINT8* module)
{
    UINT8* string;
    UINT8* data;
    module_header *header;
    guid_section_header *guid_header;
    BOOLEAN is_found;

    if(!module)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;
    data = module + sizeof(module_header);

    guid_header = (guid_section_header*) data;
    // Skipping GUID definition section in the beginning of PlatformSetupAdvancedDxe.efi module 
    if (guid_header->type == SECTION_GUID_DEFINED)
        data += guid_header->data_offset;
    else 
        return ERR_UNKNOWN_MODULE;

    
    // Searching for unicode patch string
    string = find_pattern(data, size2int(guid_header->size), PLATFORMSETUPADVANCED_UNICODE_PATCH_PATTERN, sizeof(PLATFORMSETUPADVANCED_UNICODE_PATCH_PATTERN));
    if(string)
    {
        memcpy(string, PLATFORMSETUPADVANCED_UNICODE_PATCHED_PATTERN, sizeof(PLATFORMSETUPADVANCED_UNICODE_PATCH_PATTERN));
    }
    else 
        return ERR_PATCH_STRING_NOT_FOUND;

    // Searching for all patch strings 
    is_found = FALSE;
    for (string = find_pattern(data, size2int(guid_header->size), PLATFORMSETUPADVANCED_PATCH_PATTERN, sizeof(PLATFORMSETUPADVANCED_PATCH_PATTERN));
         string;
         string = find_pattern(data, size2int(guid_header->size), PLATFORMSETUPADVANCED_PATCH_PATTERN, sizeof(PLATFORMSETUPADVANCED_PATCH_PATTERN)))
    {
        is_found = TRUE;
        // Patching
        memcpy(string, PLATFORMSETUPADVANCED_PATCHED_PATTERN, sizeof(PLATFORMSETUPADVANCED_PATCH_PATTERN));
    }
    if(!is_found)
        return ERR_PATCH_STRING_NOT_FOUND;
    
    // Correcting checksums
    return correct_checksums(module);  
}

UINT8 patch_cpupei_module(UINT8* module)
{
    UINT8* string;
    module_header *header;

    if(!module)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;

    // Searching for patch string 
    string = find_pattern(module, size2int(header->size), CPUPEI_PATCH_PATTERN, sizeof(CPUPEI_PATCH_PATTERN));
    if(!string)
        return ERR_PATCH_STRING_NOT_FOUND;

    // Patching
    memcpy(string, CPUPEI_PATCHED_PATTERN, sizeof(CPUPEI_PATCH_PATTERN));

    // Correcting checksums
    return correct_checksums(module);
}

UINT8 patch_nested_module(UINT8* module)
{
    module_header *header;
    compressed_section_header *compressed_header;
    UINT8* data;
    UINT32 data_size;
    UINT8* compressed;
    UINT32 compressed_size;
    UINT8* decompressed;
    UINT32 decompressed_size;
    UINT8* scratch;
    UINT32 scratch_size;
    UINT8* string;
    INT32 module_size_change;
    UINT8 result;
    FILE *file;


    if(!module)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;
    data = module + sizeof(module_header);
    
    // Writing file "packed.rom"
    file = fopen("packed.rom", "wb");
    if(file)
        fwrite(module, sizeof(INT8), size2int(header->size), file); 
    
    compressed_header = (compressed_section_header*) data;
    if(compressed_header->type != SECTION_COMPRESSED)
        return ERR_UNKNOWN_MODULE;
    
    data += sizeof(compressed_section_header);
    data_size = size2int(compressed_header->size) - sizeof(compressed_section_header);

    // Decompressing module data 
    switch (compressed_header->compression_type)
    {
    case COMPRESSION_TIANO:
        if (TianoGetInfo(data, data_size, &decompressed_size, &scratch_size) != EFI_SUCCESS
            ||  decompressed_size != compressed_header->decompressed_size)
            return ERR_TIANO_DECOMPRESSION_FAILED;

        decompressed = (UINT8*)malloc(decompressed_size);
        scratch = (UINT8*)malloc(scratch_size);

        if (TianoDecompress(data, data_size, decompressed, decompressed_size, scratch, scratch_size) != EFI_SUCCESS)
            return ERR_TIANO_DECOMPRESSION_FAILED;
        free(scratch);
        break;
    case COMPRESSION_LZMA:
        if (LzmaGetInfo(data, data_size, &decompressed_size, &scratch_size) != EFI_SUCCESS
            ||  decompressed_size != compressed_header->decompressed_size)
            return ERR_LZMA_DECOMPRESSION_FAILED;

        decompressed = (UINT8*)malloc(decompressed_size);
        scratch = (UINT8*)malloc(scratch_size);

        if (LzmaDecompress(data, data_size, decompressed, scratch) != EFI_SUCCESS)
            return ERR_LZMA_DECOMPRESSION_FAILED;
        free(scratch);
        break;
    case COMPRESSION_NONE:
        decompressed = data;
        decompressed_size = data_size;
        break;
    default:
        return ERR_UNKNOWN_COMPRESSION_TYPE;
    }

    // Writing file "unpacked.rom"
    file = fopen("unpacked.rom", "wb");
    if(file)
        fwrite(decompressed, sizeof(INT8), decompressed_size, file); 
    
    // Searching for PowerManagement modules 
    if (string = find_pattern(decompressed, decompressed_size, POWERMANAGEMENT_UUID, UUID_LENGTH))
    {
        // Patching PowerManagement module 
        result = patch_powermanagement_module(string);
        if (result)
            return result;
    }
    else if (string = find_pattern(decompressed, decompressed_size, POWERMANAGEMENT2_UUID, UUID_LENGTH))
    {
        // Patching PowerManagement2.efi module 
        result = patch_powermanagement2_module(string);
        if (result)
            return result;
    }
    else 
        return ERR_MODULE_NOT_FOUND;

    // Searching for PlatformSetupAdvancedDxe.efi module
    if (string = find_pattern(decompressed, decompressed_size, PLATFORMSETUPADVANCED_UUID, UUID_LENGTH))
    {
        result = patch_platformsetupadvanced_module(string);
        if (!result)
            printf("Nested PlatformSetupAdvancedDxe.efi at %08X patched.\n", string - module);
    }
    
    // Writing file "patched.rom"
    file = fopen("patched.rom", "wb");
    if(file)
        fwrite(decompressed, sizeof(INT8), decompressed_size, file); 

    // Compressing patched module 
    switch(compressed_header->compression_type)
    {
    case COMPRESSION_TIANO:
        compressed_size = 0;
        if (TianoCompress(decompressed, decompressed_size, compressed, &compressed_size) != EFI_BUFFER_TOO_SMALL)
            return ERR_TIANO_COMPRESSION_FAILED;
        compressed = (UINT8*)malloc(compressed_size);
        if (TianoCompress(decompressed, decompressed_size, compressed, &compressed_size) != EFI_SUCCESS)
            return ERR_TIANO_COMPRESSION_FAILED;
        break;
    case COMPRESSION_LZMA:
        compressed_size = 0;
        if(LzmaCompress(decompressed, decompressed_size, compressed, &compressed_size, 9) != EFI_BUFFER_TOO_SMALL)
            return ERR_LZMA_COMPRESSION_FAILED;
        compressed = (UINT8*)malloc(compressed_size);
        if (LzmaCompress(decompressed, decompressed_size, compressed, &compressed_size, 9) != EFI_SUCCESS)
            return ERR_TIANO_COMPRESSION_FAILED;
        break;
    case COMPRESSION_NONE:
        compressed = decompressed;
        compressed_size = decompressed_size;
        break;
    default:
        return ERR_UNKNOWN_COMPRESSION_TYPE;
    }
    module_size_change = compressed_size - data_size;
    // Checking that new compressed module can be inserted 
    if (module_size_change > 0) // Compressed module is bigger then original
    {
        INT32 pos;
        for(pos = 0; data[data_size+pos] == 0xFF; pos++);
        if(pos < module_size_change)
            return ERR_PATCHED_MODULE_INSERTION_FAILED;

    }
    else if (module_size_change < 0) // Compressed module is smaller then original
    {
        // Checking if there is another module after this one
        INT32 pos;
        for(pos = 0; data[data_size+pos] == 0xFF; pos++);
        if(pos < 8 && -module_size_change + pos > 7)
            return ERR_PATCHED_MODULE_INSERTION_FAILED;

        memset(data + compressed_size, 0xFF, data_size - compressed_size);
    }
    // Writing new module 
    if (compressed_header->compression_type != COMPRESSION_NONE)
    {
        memcpy(data, compressed, compressed_size);
        // Writing new compressed section size 
        int2size(compressed_size + sizeof(compressed_section_header), compressed_header->size);
        // Writing new module size 
        int2size(size2int(header->size) + module_size_change, header->size);
    }
    // Calculating new module checksums 
    header->header_checksum = 0;
    header->data_checksum = 0;
    header->header_checksum = calculate_checksum(module, sizeof(module_header) - 1);
    header->data_checksum = calculate_checksum(module + sizeof(module_header), size2int(header->size) - sizeof(module_header));

    // Writing file "repacked.rom"
    file = fopen("repacked.rom", "wb");
    if(file)
        fwrite(module, sizeof(INT8), size2int(header->size), file); 

    return ERR_PATCHED;
}

UINT8 patch_bios(UINT8* bios, UINT32 size)
{
    UINT8* module;
    UINT8* raw_file;
    UINT8* bios_end;
    UINT8 patch_result;
    BOOLEAN is_found;

    if (!bios || !size)
        return ERR_INVALID_ARGUMENT;

    bios_end = bios + size;
    module = bios;

    // Searching for all PowerManagement modules
    is_found = FALSE;
    for (module = find_pattern(bios, size, POWERMANAGEMENT_UUID, UUID_LENGTH);
        module;
        module = find_pattern(module+UUID_LENGTH, bios_end-module-UUID_LENGTH, POWERMANAGEMENT_UUID, UUID_LENGTH)) 
    {
        is_found = TRUE;
        patch_result = patch_powermanagement_module(module);
        if (!patch_result)
        {
            printf("PowerManagement module at %08X patched.\n", module - bios);
            continue;
        }

        printf("PowerManagement module at %08X not patched: ", module - bios);
        switch (patch_result)
        {
        case ERR_INVALID_ARGUMENT:
            printf("Invalid parameter.\n");
            break;
        case ERR_UNKNOWN_COMPRESSION_TYPE:
            printf("Unknown compression type.\n");
            break;
        case ERR_TIANO_DECOMPRESSION_FAILED:
            printf("Tiano decompression failed.\n");
            break;
        case ERR_LZMA_DECOMPRESSION_FAILED:
            printf("LZMA decompression failed.\n");
            break;
        case ERR_PATCH_STRING_NOT_FOUND:
            printf("Patch pattern not found.\n");
            break;
        case ERR_TIANO_COMPRESSION_FAILED:
            printf("Tiano compression failed.\n");
            break;
        case ERR_LZMA_COMPRESSION_FAILED:
            printf("LZMA compression failed.\n");
            break;
        case ERR_PATCHED_MODULE_INSERTION_FAILED:
            printf("Repacked module can not be inserted.\n");
            break;
        default:
            printf("Unknown error.\n");
            break;
        }
    }
    if (!is_found)
        printf("PowerManagement module not found.\n");    

    // Searching for all nested PowerManagement modules
    is_found = FALSE;
    for (module = find_pattern(bios, size, NESTED_UUID, UUID_LENGTH);
        module;
        module = find_pattern(module+UUID_LENGTH, bios_end-module-UUID_LENGTH, NESTED_UUID, UUID_LENGTH)) 
    {
        is_found = TRUE;
        patch_result = patch_nested_module(module);

        if (!patch_result)
        {
            printf("Nested PowerManagement module at %08X patched.\n", module - bios);
            continue;
        }

        printf("Nested PowerManagement module at %08X not patched: ", module - bios);
        switch (patch_result)
        {
        case ERR_INVALID_ARGUMENT:
            printf("Invalid argument.\n");
            break;
        case ERR_UNKNOWN_COMPRESSION_TYPE:
            printf("Unknown compression type.\n");
            break;
        case ERR_TIANO_DECOMPRESSION_FAILED:
            printf("Tiano decompression failed.\n");
            break;
        case ERR_LZMA_DECOMPRESSION_FAILED:
            printf("LZMA decompression failed.\n");
            break;
        case ERR_PATCH_STRING_NOT_FOUND:
            printf("Patch pattern not found.\n");
            break;
        case ERR_TIANO_COMPRESSION_FAILED:
            printf("Tiano compression failed.\n");
            break;
        case ERR_LZMA_COMPRESSION_FAILED:
            printf("LZMA compression failed.\n");
            break;
        case ERR_PATCHED_MODULE_INSERTION_FAILED:
            printf("Repacked module can not be inserted.\n");
            break;
        case ERR_MODULE_NOT_FOUND:
            printf("PowerManagement module not found in nested module.\n");
            break;
        default:
            printf("Unknown error.\n");
            break;
        }

    }
    if (!is_found)
        printf("Nested PowerManagement module not found.\n"); 

    // Searching for all nested PowerManagement2.efi modules
    is_found = FALSE;
    for (module = find_pattern(bios, size, PHOENIX_NESTED_UUID, UUID_LENGTH);
        module;
        module = find_pattern(module+UUID_LENGTH, bios_end-module-UUID_LENGTH, PHOENIX_NESTED_UUID, UUID_LENGTH)) 
    {
        is_found = TRUE;
        patch_result = patch_nested_module(module);

        if (!patch_result)
        {
            printf("Nested PowerManagement2.efi module at %08X patched.\n", module - bios);
            
            // Fixing RAW file checksum in Dell BIOSes
            raw_file = find_pattern(bios, size, DELL_RAW_FILE_GUID, UUID_LENGTH);
            if(raw_file)
                if(!correct_checksums(raw_file))
                    printf("Dell RAW file checksums corrected.\n");
            continue;
        }

        printf("Nested PowerManagement2.efi module at %08X not patched: ", module - bios);
        switch (patch_result)
        {
        case ERR_INVALID_ARGUMENT:
            printf("Invalid argument.\n");
            break;
        case ERR_UNKNOWN_COMPRESSION_TYPE:
            printf("Unknown compression type.\n");
            break;
        case ERR_TIANO_DECOMPRESSION_FAILED:
            printf("Tiano decompression failed.\n");
            break;
        case ERR_LZMA_DECOMPRESSION_FAILED:
            printf("LZMA decompression failed.\n");
            break;
        case ERR_PATCH_STRING_NOT_FOUND:
            printf("Patch pattern not found.\n");
            break;
        case ERR_TIANO_COMPRESSION_FAILED:
            printf("Tiano compression failed.\n");
            break;
        case ERR_LZMA_COMPRESSION_FAILED:
            printf("LZMA compression failed.\n");
            break;
        case ERR_PATCHED_MODULE_INSERTION_FAILED:
            printf("Repacked module can not be inserted.\n");
            break;
        case ERR_MODULE_NOT_FOUND:
            printf("PowerManagement2.efi module not found in nested module.\n");
            break;
        default:
            printf("Unknown error.\n");
            break;
        }
    }
    if (!is_found)
        printf("Nested PowerManagement2.efi module not found.\n"); 

    // Searching for all CpuPei modules
    is_found = FALSE;
    for (module = find_pattern(bios, size, CPUPEI_UUID, UUID_LENGTH);
        module;
        module = find_pattern(module+UUID_LENGTH, bios_end-module-UUID_LENGTH, CPUPEI_UUID, UUID_LENGTH)) 
    {
        is_found = TRUE;
        patch_result = patch_cpupei_module(module);

        if (!patch_result)
        {
            printf("CpuPei module at %08X patched.\n", module - bios);
            continue;
        }

        printf("CpuPei module at %08X not patched: ", module - bios);
        switch (patch_result)
        {
        case ERR_INVALID_ARGUMENT:
            printf("Invalid argument.\n");
            break;
        case ERR_PATCH_STRING_NOT_FOUND:
            printf("Patch pattern not found.\n");
            break;
        default:
            printf("Unknown error.\n");
            break;
        }
    }
    if (!is_found)
        printf("CpuPei module not found.\n");   

    return ERR_PATCHED;
}