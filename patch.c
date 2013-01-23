/* Patch Implementation

  Copyright (c) 2012, Nikolaj Schlej. All rights reserved.
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#include "patch_int.h"

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

UINT8 insert_gap_after(UINT8* module, UINT8* end, UINT32 gap_size)
{
    UINT8 *gap;
    module_header *header;
    module_header *gap_header;
    UINT32 size;
    UINT32 allignment;

    if (!module || !end || end <= module)
        return ERR_INVALID_ARGUMENT;

    // Checking for existing GAP module
    // Determining next module position
    header = (module_header *) module;
    gap = module + size2int(header->size);
    size = gap - module;
    if (size % MODULE_ALLIGNMENT)
        allignment = MODULE_ALLIGNMENT - size % MODULE_ALLIGNMENT;
    else
        allignment = 0;
    gap += allignment;
    // Checking for next module to be GAP
    if (find_pattern(gap, sizeof(GAP_UUID), GAP_UUID, sizeof(GAP_UUID)))
    {
        header = (module_header *) gap;
        // Using found GAP module as free space
        gap_size += size2int(header->size) + allignment;
    }

    size = end - module;
    if (size % MODULE_ALLIGNMENT)
        allignment = MODULE_ALLIGNMENT - size % MODULE_ALLIGNMENT;
    else
        allignment = 0;

    gap_size -= allignment;

    if (gap_size < sizeof(module_header))
        return ERR_INVALID_ARGUMENT;
    
    memset(end, 0xFF, allignment);

    gap = end + allignment;
    gap_header = (module_header*) gap;

    // Constructing gap header
    memcpy(gap_header->guid, GAP_UUID, sizeof(GAP_UUID));
    gap_header->type = TYPE_GAP;
    gap_header->attributes = ATTRIBUTES_GAP;
    gap_header->state = STATE_STD;
    int2size(gap_size, gap_header->size);

    // Filling gap with 0xFF byte
    memset(gap + sizeof(module_header), 0xFF, gap_size - sizeof(module_header));
    
    // Calculating checksums
    gap_header->header_checksum = 0;
    gap_header->data_checksum = 0;
    gap_header->header_checksum = calculate_checksum(gap, sizeof(module_header) - 1);
    gap_header->data_checksum = 0xAA;

    printf("Gap module inserted after repacked module.\n");

    return ERR_PATCHED;
}

UINT8 patch_powermanagement_module(UINT8* module, UINT8 start_patch)
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
    UINT32 freespace_length;
    UINT8* end;

    if(!module || start_patch >= PATCHED_PATTERNS_COUNT)
        return ERR_INVALID_ARGUMENT;
    
    header = (module_header*) module;
    if (header->state != STATE_STD)
        return ERR_NOT_MODULE; 

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
    compressed = NULL;
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
        if (!decompressed || !scratch)
            return ERR_MEMORY_ALLOCATION_FAILED;

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

    // Searching for specific patch patterns first 
    string = find_pattern(decompressed, decompressed_size, POWERMANAGEMENT_PATCH_PATTERN_80FB01, sizeof(POWERMANAGEMENT_PATCH_PATTERN_80FB01));
    if(string)
    {
        // Patching first 3 bytes with 0x90
        memset(string, 0x90, 3);
        string += 3;
    }
    else
        // Searching for generic patch pattern
        string = find_pattern(decompressed, decompressed_size, POWERMANAGEMENT_PATCH_PATTERN, sizeof(POWERMANAGEMENT_PATCH_PATTERN));
    if (!string)
        return ERR_PATCH_STRING_NOT_FOUND;

    // Trying all patched strings beginning from start_patch
    is_patched = FALSE;
    for(current_patch = start_patch; current_patch < PATCHED_PATTERNS_COUNT; current_patch++)
    {
        // Patching found string with current patch 
        memcpy(string, POWERMANAGEMENT_PATCHED_PATTERNS[current_patch], sizeof(POWERMANAGEMENT_PATCH_PATTERN));

        // Compressing patched module 
        switch(compressed_header->compression_type)
        {
        case COMPRESSION_TIANO:
            compressed_size = 0;
            if (TianoCompress(decompressed, decompressed_size, compressed, &compressed_size) != EFI_BUFFER_TOO_SMALL)
                return ERR_TIANO_COMPRESSION_FAILED;
            compressed = (UINT8*)malloc(compressed_size);
            if (!compressed)
                return ERR_MEMORY_ALLOCATION_FAILED;
            if (TianoCompress(decompressed, decompressed_size, compressed, &compressed_size) != EFI_SUCCESS)
                return ERR_TIANO_COMPRESSION_FAILED;
            break;
        case COMPRESSION_LZMA:
            compressed_size = 0;
            if(LzmaCompress(decompressed, decompressed_size, compressed, &compressed_size) != EFI_BUFFER_TOO_SMALL)
                return ERR_LZMA_COMPRESSION_FAILED;
            compressed = (UINT8*)malloc(compressed_size);
            if (!compressed)
                return ERR_MEMORY_ALLOCATION_FAILED;
            if (LzmaCompress(decompressed, decompressed_size, compressed, &compressed_size) != EFI_SUCCESS)
                return ERR_TIANO_COMPRESSION_FAILED;
            grow = data_size > compressed_size ? data_size - compressed_size : compressed_size - data_size;
            break;
        case COMPRESSION_NONE:
            compressed = decompressed;
            compressed_size = decompressed_size;
            break;
        default:
            return ERR_UNKNOWN_COMPRESSION_TYPE;
        }

        // Checking compressed data size 
        if (data_size < compressed_size)
        {
            grow = compressed_size - data_size;
            end = data + data_size;
            for (freespace_length = 0; *end++ == 0xFF; freespace_length++);
            if (grow > freespace_length)
                continue;
        }
        else if (data_size > compressed_size)
        {
            grow = data_size - compressed_size;
            end = data + data_size;
            for (freespace_length = 0; *end++ == 0xFF; freespace_length++);
            if (grow + freespace_length >= 8)
                if (insert_gap_after(module, data + compressed_size, grow))
                    continue;
        }

        is_patched = TRUE;
        break;
    }

    if (!is_patched)
        return ERR_PATCHED_MODULE_INSERTION_FAILED;

    // Writing new module 
    if (data_size > compressed_size)
        memset(data + compressed_size, 0xFF, data_size - compressed_size);
    if (compressed_header->compression_type != COMPRESSION_NONE)
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

UINT8 patch_powermanagement2_module(UINT8* module,  UINT8 start_patch)
{
    module_header* header; 
    UINT8* string;
    UINT8* data;
    guid_section_header *guid_header;

    if(!module || start_patch >= PATCHED_PATTERNS_COUNT)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;
    if (header->state != STATE_STD)
        return ERR_NOT_MODULE; 

    data = module + sizeof(module_header);

    guid_header = (guid_section_header*) data;
    // Skipping GUID definition section in the beginning of PowerManagement2.efi module 
    if (guid_header->type == SECTION_GUID_DEFINED)
        data += guid_header->data_offset;
    else 
        return ERR_UNKNOWN_MODULE;

    // Searching for specific patch patterns first 
    string = find_pattern(data, size2int(guid_header->size), POWERMANAGEMENT_PATCH_PATTERN_80FB01, sizeof(POWERMANAGEMENT_PATCH_PATTERN_80FB01));
    if(string)
    {
        // Patching first 3 bytes with 0x90
        memset(string, 0x90, 3);
        string += 3;
    }
    else
        // Searching for generic patch pattern
        string = find_pattern(data, size2int(guid_header->size), POWERMANAGEMENT_PATCH_PATTERN, sizeof(POWERMANAGEMENT_PATCH_PATTERN));
    if (!string)
        return ERR_PATCH_STRING_NOT_FOUND;

    // Patching
    memcpy(string, POWERMANAGEMENT_PATCHED_PATTERNS[start_patch], sizeof(POWERMANAGEMENT_PATCH_PATTERN));

    // Correcting checksums
    return correct_checksums(module);  
}

UINT8 patch_platformsetupadvanced_module(UINT8* module)
{
    module_header* header; 
    UINT8* string;
    UINT8* data;
    guid_section_header *guid_header;
    BOOLEAN is_found;

    if(!module)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;
    if (header->state != STATE_STD)
        return ERR_NOT_MODULE; 

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
    module_header* header; 
    UINT8* string;

    if(!module)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;
    if (header->state != STATE_STD)
        return ERR_NOT_MODULE; 

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
    UINT8 current_patch;
    UINT8 result;
    BOOLEAN is_patched;
    BOOLEAN is_module_patched;

    if(!module)
        return ERR_INVALID_ARGUMENT;

    header = (module_header*) module;
    if (header->state != STATE_STD)
        return ERR_NOT_MODULE; 
    
    data = module + sizeof(module_header);
    
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
        if (!decompressed || !scratch)
            return ERR_MEMORY_ALLOCATION_FAILED;

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
        if (!decompressed || !scratch)
            return ERR_MEMORY_ALLOCATION_FAILED;

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

    // Searching for PlatformSetupAdvancedDxe.efi module
    string = find_pattern(decompressed, decompressed_size, PLATFORMSETUPADVANCED_UUID, UUID_LENGTH);
    if (string)
    {
        result = patch_platformsetupadvanced_module(string);
        if (!result)
            printf("Nested PlatformSetupAdvancedDxe.efi at %08X patched.\n", string - module);
    }

    // Trying to patch PowerManagement modules with all patch patterns
    is_patched = FALSE;
    scratch = (UINT8*)malloc(decompressed_size);
    if(!scratch)
        return ERR_MEMORY_ALLOCATION_FAILED;

    for(current_patch = 0; current_patch < PATCHED_PATTERNS_COUNT; current_patch++)
    {
        printf("Trying to apply patch #%d\n", current_patch + 1);

        // Making a copy of decompressed module
        memcpy(scratch, decompressed, decompressed_size);

        is_module_patched = FALSE;

        // Searching for all PowerManagement modules 
        for (string = find_pattern(scratch, decompressed_size, POWERMANAGEMENT_UUID, UUID_LENGTH);
             string;
             string = find_pattern(string + UUID_LENGTH, decompressed_size - (string - scratch) - UUID_LENGTH, POWERMANAGEMENT_UUID, UUID_LENGTH))
        {
            // Patching PowerManagement module 
            result = patch_powermanagement_module(string, current_patch);
            
            if (!result)
            {
                printf("Nested PowerManagement module at %08X patched.\n", string - module);
                is_module_patched = TRUE;
                continue;
            }

            printf("Nested PowerManagement module at %08X not patched: ", string - module);
            switch (result)
            {
            case ERR_INVALID_ARGUMENT:
                printf("Invalid parameter.\n");
                break;
            case ERR_NOT_MODULE:
                printf("Unknown module state.\n");
                break;
            case ERR_UNKNOWN_MODULE:
                printf("Unknown module structure.\n");
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
            case ERR_MEMORY_ALLOCATION_FAILED:
                printf("Memory allocation failed.\n");
                break;
            default:
                printf("Unknown error.\n");
                break;
            }
        }

        // Searching for all PowerManagement2.efi modules 
        for (string = find_pattern(scratch, decompressed_size, POWERMANAGEMENT2_UUID, UUID_LENGTH);
             string;
             string = find_pattern(string + UUID_LENGTH, decompressed_size - (string - scratch) - UUID_LENGTH, POWERMANAGEMENT2_UUID, UUID_LENGTH))
        {
            // Patching PowerManagement2.efi module 
            result = patch_powermanagement2_module(string, current_patch);
            
            if (!result)
            {
                printf("Nested PowerManagement2.efi module at %08X patched.\n", string - module);
                is_module_patched = TRUE;
                continue;
            }

            printf("Nested PowerManagement2.efi module at %08X not patched: ", string - module);
            switch (result)
            {
            case ERR_INVALID_ARGUMENT:
                printf("Invalid parameter.\n");
                break;
            case ERR_NOT_MODULE:
                printf("Unknown module state.\n");
                break;
            case ERR_UNKNOWN_MODULE:
                printf("Unknown module structure.\n");
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
            case ERR_MEMORY_ALLOCATION_FAILED:
                printf("Memory allocation failed.\n");
                break;
            default:
                printf("Unknown error.\n");
                break;
            }
        }
        
        if (!is_module_patched)
            return ERR_MODULE_NOT_FOUND;
        
        // Compressing patched module 
        switch(compressed_header->compression_type)
        {
        case COMPRESSION_TIANO:
            compressed = 0;
            compressed_size = 0;
            if (TianoCompress(scratch, decompressed_size, compressed, &compressed_size) != EFI_BUFFER_TOO_SMALL)
                return ERR_TIANO_COMPRESSION_FAILED;
            compressed = (UINT8*)malloc(compressed_size);
            if(!compressed)
                return ERR_MEMORY_ALLOCATION_FAILED;
            if (TianoCompress(scratch, decompressed_size, compressed, &compressed_size) != EFI_SUCCESS)
                return ERR_TIANO_COMPRESSION_FAILED;
            break;
        case COMPRESSION_LZMA:
            compressed = 0;
            compressed_size = 0;
            if(LzmaCompress(scratch, decompressed_size, compressed, &compressed_size) != EFI_BUFFER_TOO_SMALL)
                return ERR_LZMA_COMPRESSION_FAILED;
            compressed = (UINT8*)malloc(compressed_size);
            if(!compressed)
                return ERR_MEMORY_ALLOCATION_FAILED;
            if (LzmaCompress(scratch, decompressed_size, compressed, &compressed_size) != EFI_SUCCESS)
                return ERR_TIANO_COMPRESSION_FAILED;
            break;
        case COMPRESSION_NONE:
            compressed = scratch;
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
            {
                printf ("Patched module too big after compression.\n");
                continue;
            }
        }
        else if (module_size_change < 0) // Compressed module is smaller then original
        {
            // Checking if there is another module after this one
            INT32 pos;
            for(pos = 0; data[data_size+pos] == 0xFF; pos++);
            if (pos < 8 && -module_size_change + pos > 7)
            {
                if (insert_gap_after(module, data + compressed_size, data_size - compressed_size))
                {
                    printf ("Patched module is smaller then original after compression, but gap module can't be inserted.\n");
                    continue;
                }
            }
            else
                memset(data + compressed_size, 0xFF, data_size - compressed_size);
        }
        is_patched = TRUE;
        break;
    }
    free(scratch);

    if(!is_patched)
        return ERR_PATCHED_MODULE_INSERTION_FAILED;

    // Writing new module 
    if (compressed_header->compression_type != COMPRESSION_NONE)
    {
        memcpy(data, compressed, compressed_size);
        // Writing new compressed section size 
        int2size(compressed_size + sizeof(compressed_section_header), compressed_header->size);
        // Writing new module size 
        int2size(size2int(header->size) + module_size_change, header->size);
    }

    // Correcting checksums
    return correct_checksums(module);
}

BOOLEAN patch_bios(UINT8* bios, UINT32 size)
{
    UINT8* module;
    UINT8* raw_file;
    UINT8* bios_end;
    UINT8 patch_result;
    BOOLEAN is_found;
    BOOLEAN is_patched;

    if (!bios || !size)
        return ERR_INVALID_ARGUMENT;

    bios_end = bios + size;

    is_patched = FALSE;

    // Searching for all PowerManagement modules
    is_found = FALSE;
    for (module = find_pattern(bios, size, POWERMANAGEMENT_UUID, UUID_LENGTH);
        module;
        module = find_pattern(module+UUID_LENGTH, bios_end-module-UUID_LENGTH, POWERMANAGEMENT_UUID, UUID_LENGTH)) 
    {
        is_found = TRUE;
        patch_result = patch_powermanagement_module(module, 0);
        if (!patch_result)
        {
            printf("PowerManagement module at %08X patched.\n", module - bios);
            is_patched = TRUE;
            continue;
        }

        printf("PowerManagement module at %08X not patched: ", module - bios);
        switch (patch_result)
        {
        case ERR_INVALID_ARGUMENT:
            printf("Invalid parameter.\n");
            break;
        case ERR_UNKNOWN_MODULE:
            printf("Unknown module structure.\n");
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
            printf("Repacked module can't be inserted.\n");
            break;
        case ERR_MEMORY_ALLOCATION_FAILED:
            printf("Memory allocation failed.\n");
            break;
        default:
            printf("Unknown error.\n");
            break;
        }
    }
    if (!is_found)
        printf("PowerManagement modules not found.\n");    

    // Searching for all common nested modules
    is_found = FALSE;
    for (module = find_pattern(bios, size, AMI_NEST_UUID, UUID_LENGTH);
        module;
        module = find_pattern(module+UUID_LENGTH, bios_end-module-UUID_LENGTH, AMI_NEST_UUID, UUID_LENGTH)) 
    {
        is_found = TRUE;
        patch_result = patch_nested_module(module);

        if (!patch_result)
        {
            printf("AMI nest module at %08X patched.\n", module - bios);
            is_patched = TRUE;
            continue;
        }

        printf("AMI nest module at %08X not patched: ", module - bios);
        switch (patch_result)
        {
        case ERR_INVALID_ARGUMENT:
            printf("Invalid argument.\n");
            break;
        case ERR_UNKNOWN_MODULE:
            printf("Unknown module structure.\n");
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
            printf("Repacked module can't be inserted.\n");
            break;
        case ERR_MODULE_NOT_FOUND:
            printf("PowerManagement modules not found in nested module.\n");
            break;
        case ERR_MEMORY_ALLOCATION_FAILED:
            printf("Memory allocation failed.\n");
            break;
        default:
            printf("Unknown error.\n");
            break;
        }

    }
    if (!is_found)
        printf("AMI nest modules not found.\n"); 

    // Searching for all nested PowerManagement2.efi modules
    is_found = FALSE;
    for (module = find_pattern(bios, size, PHOENIX_NEST_UUID, UUID_LENGTH);
        module;
        module = find_pattern(module+UUID_LENGTH, bios_end-module-UUID_LENGTH, PHOENIX_NEST_UUID, UUID_LENGTH)) 
    {
        is_found = TRUE;
        patch_result = patch_nested_module(module);

        if (!patch_result)
        {
            printf("Phoenix nest module at %08X patched.\n", module - bios);
            is_patched = TRUE;

            // Fixing RAW file checksum in Dell BIOSes
            raw_file = find_pattern(bios, size, DELL_RAW_FILE_UUID, UUID_LENGTH);
            if(raw_file)
                if(!correct_checksums(raw_file))
                    printf("Dell RAW file checksums corrected.\n");
            continue;
        }

        printf("Phoenix nest module at %08X not patched: ", module - bios);
        switch (patch_result)
        {
        case ERR_INVALID_ARGUMENT:
            printf("Invalid argument.\n");
            break;
        case ERR_UNKNOWN_MODULE:
            printf("Unknown module structure.\n");
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
            printf("Repacked module can't be inserted.\n");
            break;
        case ERR_MODULE_NOT_FOUND:
            printf("PowerManagement modules not found in nested module.\n");
            break;
        case ERR_MEMORY_ALLOCATION_FAILED:
            printf("Memory allocation failed.\n");
            break;
        default:
            printf("Unknown error.\n");
            break;
        }
    }
    if (!is_found)
        printf("Phoenix nest modules not found.\n"); 

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
            is_patched = TRUE;
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
        printf("CpuPei modules not found.\n");   

    return is_patched;
}