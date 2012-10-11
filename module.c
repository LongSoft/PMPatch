#include "module.h"

const UINT8 PWRMGMT_UUID[] =             {'\x70','\x39','\x78','\x8C',
                                          '\x2A','\xF0','\x4D','\x4A',
                                          '\xAF','\x09','\x87','\x97',
                                          '\xA5','\x1E','\xEC','\x8D'};
const UINT8 CPUPEI_UUID[] =              {'\xA9','\xAF','\xB5','\x2B',
                                          '\x33','\xFF','\x7B','\x41',
                                          '\x84','\x97','\xCB','\x77',
                                          '\x3C','\x2B','\x93','\xBF'};
const UINT8 VOLUME_TOP_UUID[] =          {'\x2E','\x06','\xA0','\x1B',
                                          '\x79','\xC7','\x82','\x45',
                                          '\x85','\x66','\x33','\x6A',
                                          '\xE8','\xF7','\x8F','\x09'};
const UINT8 PATCH_STRING[] =             {'\x80','\xFB','\x01',       
                                          '\x75','\x08',              
                                          '\x0F','\xBA','\xE8','\x0F',
                                          '\x89','\x44','\x24','\x30'};
const UINT8 PATCHED_STRING[] =           {'\x90','\x90','\x90',       
                                          '\x90','\x90',              
                                          '\x90','\x90','\x90','\x90',
                                          '\x90','\x90','\x90','\x90'};
const UINT8* PATCH_MODULE_ERROR_MESSAGES[] = {
    "No error.\n",
    "Module data corrupted.\n",
    "Memory allocation error.\n",
    "Module decompression failed.\n",
    "Patch pattern not found in module.\n",
    "Buffer size query failed.\n",
    "Module compression failed.\n",
    "Not enough space to insert compressed module.\n",
    "Method parameters are wrong.\n"
};


UINT8* find_pattern(UINT8* string, UINT32 slen, const UINT8* pattern, UINT32 plen)
{
    size_t scan = 0;
    size_t bad_char_skip[256];
    size_t last;

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

int calculate_checksum(UINT8* data, UINT32 length, UINT8* checksum)
{
    UINT8 counter;

    if(!data || !length || !checksum)
        return 0;
    counter = 0;
    while(length--)
        counter += data[length];
    *checksum = ~counter + 1;
    return 1;
}

int int2size(UINT32 size, UINT8* module_size)
{
    if(!module_size)
        return 0;
    module_size[2] = (UINT8) (((size) >> 16));
    module_size[1] = (UINT8) (((size) >>  8));
    module_size[0] = (UINT8) (((size)      ));
    return 1;
}

int size2int(UINT8* module_size, UINT32* size)
{
    if(!module_size || !size)
        return 0;

    *size = (module_size[2] << 16) + 
            (module_size[1] << 8) + 
             module_size[0];
    return 1;
}

int patch_module(UINT8* module, UINT8* error_code)
{
    UINT32 module_size;
    UINT32 data_size;
    UINT8* data;
    UINT8* decompressed;
    UINT8* string;
    UINT8* scratch;
    UINT8* end;
    UINT32 decompressed_size;
    UINT32 scratch_size;
    UINT32 grow;
    UINT8 module_size_bytes[3];
    UINT8 module_checksum;
    UINT8 header_checksum;

    /* Reading module size */
    if(!module  || !error_code || !size2int(module + MODULE_SIZE_OFFSET, &module_size))
    {
        *error_code = 8;
        return 0;
    }

    /* Setting pointer and size to module body */
    data = module + MODULE_DATA_OFFSET;
    data_size = module_size - MODULE_DATA_OFFSET;

    /* Checking file compression algorithm to be Tiano and receiving buffers sizes for module extraction */
    if(!EfiGetInfo(data, data_size, &decompressed_size, &scratch_size) == EFI_SUCCESS)
    {
        *error_code = 1;
        return 0;
    }

    /* Allocating memory for buffers */
    decompressed = (UINT8*)malloc(decompressed_size);
    scratch = (UINT8*)malloc(scratch_size);
    if(!decompressed || !scratch)
    {
        *error_code = 2;
        goto error;
    }
    
    /* Trying to unpack module */
    if(TianoDecompress(data, data_size, decompressed, decompressed_size, scratch, scratch_size) != EFI_SUCCESS)
    {
        *error_code = 3;
        goto error;
    }
    
    /*Searching for bytes to patch */
    string = find_pattern(decompressed, decompressed_size, PATCH_STRING, sizeof(PATCH_STRING));
    if(!string)
    {
        *error_code = 4;
        goto error;
    }
    /* Patching unpacked module */
    memcpy(string, PATCHED_STRING, sizeof(PATCHED_STRING));
    
    /* Determining buffer size for compressed module */
    scratch_size = 0;
    if(TianoCompress(decompressed, decompressed_size, scratch, &scratch_size) != EFI_BUFFER_TOO_SMALL)
    {
        *error_code = 5;
        goto error;
    }
    
    /* Reallocating buffer */
    scratch = (UINT8*)realloc(scratch, scratch_size);

    /* Compressing modified module */
    if(TianoCompress(decompressed, decompressed_size, scratch, &scratch_size) != EFI_SUCCESS)
    {
        *error_code = 6;
        goto error;
    }

    /* Checking size */
    if (data_size < scratch_size)
    {
        grow = scratch_size - data_size;
        end = module + MODULE_DATA_OFFSET + data_size;
        /* Checking that there are free space after the module */
        while(grow--)
            if(*end-- != 0xFF)
            {
                *error_code = 7;
                goto error;
            }
    }
    else if (data_size > scratch_size)
    {
        grow = data_size - scratch_size;
        end = module + MODULE_DATA_OFFSET + data_size - 1;
        while(grow--)
            *end-- = 0xFF; 
    }

    /* Writing new module sizes */
    if(!int2size(scratch_size + MODULE_DATA_OFFSET, module_size_bytes))
    {
        *error_code = 8;
        goto error;
    }
    memcpy(module + MODULE_SIZE_OFFSET, module_size_bytes, 3);
    if(!int2size(scratch_size + MODULE_COMPRESSED_DATA_OFFSET, module_size_bytes))
    {
        *error_code = 8;
        goto error;
    }
    memcpy(module + MODULE_COMPRESSED_SIZE_OFFSET, module_size_bytes, 3);

    /* Writing new compressed data*/
    memcpy(module + MODULE_DATA_OFFSET, scratch, scratch_size);

    /* Calculating checksums*/
    module[MODULE_DATA_CHECKSUM_OFFSET] = 0;
    module[MODULE_HEADER_CHECKSUM_OFFSET] = 0;

    /* Calculating data checksum*/
    if(!calculate_checksum(module, MODULE_DATA_CHECKSUM_START - 1, &header_checksum))
    {
        *error_code = 8;
        goto error;
    }
    module[MODULE_HEADER_CHECKSUM_OFFSET] = header_checksum;

    /* Calculating header checksum*/
    if(!calculate_checksum(module + MODULE_DATA_CHECKSUM_START, scratch_size + MODULE_DATA_OFFSET - MODULE_DATA_CHECKSUM_START, &module_checksum))
    {
        *error_code = 8;
        goto error;
    }
    module[MODULE_DATA_CHECKSUM_OFFSET] = module_checksum;
    
    /* Patch complete */
    *error_code = 0;

    /* Cleaning */
    free(decompressed);
    free(scratch);
    return 1;
error:
    /* Cleaning */
    free(decompressed);
    free(scratch);
    return 0;
}