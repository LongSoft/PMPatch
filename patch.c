#include "patch.h"

const UINT8 PWRMGMT_UUID[] =             {0x70,0x39,0x78,0x8C,
                                          0x2A,0xF0,0x4D,0x4A,
                                          0xAF,0x09,0x87,0x97,
                                          0xA5,0x1E,0xEC,0x8D};
const UINT8 CPUPEI_UUID[] =              {0xA9,0xAF,0xB5,0x2B,
                                          0x33,0xFF,0x7B,0x41,
                                          0x84,0x97,0xCB,0x77,
                                          0x3C,0x2B,0x93,0xBF};
const UINT8 VOLUME_TOP_UUID[] =          {0x2E,0x06,0xA0,0x1B,
                                          0x79,0xC7,0x82,0x45,
                                          0x85,0x66,0x33,0x6A,
                                          0xE8,0xF7,0x8F,0x09};
const UINT8 PWRMGMT_PATCH_STRING[] =     {0x80,0xFB,0x01,       
                                          0x75,0x08,              
                                          0x0F,0xBA,0xE8,0x0F,
                                          0x89,0x44,0x24,0x30};
const UINT8 PWRMGMT_PATCHED_STRINGS[][13] =  {
    {0x80,0xFB,0x01,0xEB,0x08,0x0F,0xBA,0xE8,0x0F,0x89,0x44,0x24,0x30},
    {0x80,0xFB,0x01,0xEB,0x08,0x90,0x90,0x90,0x90,0x89,0x44,0x24,0x30},
    {0x80,0xFB,0x01,0xEB,0x08,0x0F,0xBA,0xE8,0x0F,0x90,0x90,0x90,0x90},
    {0x80,0xFB,0x01,0xEB,0x08,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90},
    {0x90,0x90,0x90,0xEB,0x08,0x0F,0xBA,0xE8,0x0F,0x89,0x44,0x24,0x30},
    {0x90,0x90,0x90,0xEB,0x08,0x0F,0xBA,0xE8,0x0F,0x90,0x90,0x90,0x90},
    {0x90,0x90,0x90,0xEB,0x08,0x90,0x90,0x90,0x90,0x89,0x44,0x24,0x30},
    {0x90,0x90,0x90,0xEB,0x08,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90},
    {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90},
                                             };
const UINT32 PWRMGMT_PATCHED_STRINGS_COUNT = 
    sizeof(PWRMGMT_PATCHED_STRINGS)/sizeof(PWRMGMT_PATCHED_STRINGS[0]);
const UINT8 CPUPEI_PATCH_STRING[] =      {0x80,0x00,0x18,0xEB,
                                          0x05,0x0D,0x00,0x80};
const UINT8 CPUPEI_PATCHED_STRING[] =    {0x00,0x00,0x18,0xEB,
                                          0x05,0x0D,0x00,0x00};

const UINT8* PATCH_PWRMGMT_ERROR_MESSAGES[] = {
    "No error.\n",
    "Method parameters are wrong.\n",
    "Module data corrupted.\n",
    "Memory allocation error.\n",
    "Module decompression failed.\n",
    "Patch pattern not found in module.\n",
    "Buffer size query failed.\n",
    "Module compression failed.\n",
    "Not enough space to insert compressed module.\n"
};

const UINT8* PATCH_CPUPEI_ERROR_MESSAGES[] = {
    "No error.\n",
    "Method parameters are wrong.\n",
    "Patch pattern not found in module.\n"
};

/* Implementation of GNU memmem function using Boyer-Moore-Horspool algorithm */
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
    module_size[2] = (UINT8) ((size) >> 16);
    module_size[1] = (UINT8) ((size) >>  8);
    module_size[0] = (UINT8) ((size)      );
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

int patch_powermanagement_module(UINT8* module, UINT8* error_code)
{
    FILE* file;

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
    UINT32 current_patch;
    BOOLEAN patched;
    UINT8 module_size_bytes[3];
    UINT8 module_checksum;
    UINT8 header_checksum;
    UINT8 algorithm;

    /* Reading module size */
    if(!module  || !error_code || !size2int(module + MODULE_SIZE_OFFSET, &module_size))
    {
        *error_code = 1;
        return 0;
    }

    /* Setting up data pointer and size */
    data = module + PWRMGMT_DATA_OFFSET;
    data_size = module_size - PWRMGMT_DATA_OFFSET;

    /* Checking file compression and receiving buffers sizes */
    if(TianoGetInfo(data, data_size, &decompressed_size, &scratch_size) != EFI_SUCCESS)
    {
        *error_code = 2;
        return 0;
    }

    /* Allocating memory for buffers */
    decompressed = (UINT8*)malloc(decompressed_size);
    scratch = (UINT8*)malloc(scratch_size);
    if(!decompressed || !scratch)
    {
        *error_code = 3;
        goto error;
    }
    
    /* Writing compressed data to file */
    /*file = fopen("packed.bin", "wb");
    fwrite(data, 1, data_size, file);
    fclose(file);*/
    
    /* Trying to unpack module using Tiano decompression algorithm */
    algorithm = ALG_TIANO;
    if(TianoDecompress(data, data_size, decompressed, decompressed_size, scratch, scratch_size) != EFI_SUCCESS)
    {
        /* Trying to unpack module using LZMA decompression algorithm*/
        if(LzmaGetInfo(data, data_size, &decompressed_size, &scratch_size) != EFI_SUCCESS)
        {
            *error_code = 2;
            goto error;
        }

        decompressed = (UINT8*)realloc(decompressed, decompressed_size);
        scratch = (UINT8*)realloc(scratch, scratch_size);

        algorithm = ALG_LZMA;
        if(LzmaDecompress(data, data_size, decompressed, scratch) != EFI_SUCCESS)
        {
            *error_code = 4;
            goto error;
        }
    }
    
    /* Writing decompressed data to file */
    /*file = fopen("unpacked.bin", "wb");
    fwrite(decompressed, 1, decompressed_size, file);
    fclose(file);*/

    /*Searching for byte string to patch */
    string = find_pattern(decompressed, decompressed_size, PWRMGMT_PATCH_STRING, sizeof(PWRMGMT_PATCH_STRING));
    if(!string)
    {
        *error_code = 5;
        goto error;
    }
    
    /* Trying different patches to fit new module */
    for(current_patch = 0; current_patch < PWRMGMT_PATCHED_STRINGS_COUNT; current_patch++)
    {
	    patched = FALSE;

        /* Patching */
        memcpy(string, PWRMGMT_PATCHED_STRINGS[current_patch], sizeof(PWRMGMT_PATCHED_STRINGS[current_patch]));
    
        /* Compressing module */
        scratch_size = 0;
        if(algorithm == ALG_TIANO)
        {
            /* Determining buffer size for module compression */
            if(TianoCompress(decompressed, decompressed_size, scratch, &scratch_size) != EFI_BUFFER_TOO_SMALL)
            {
                *error_code = 6;
                goto error;
            }
    
            /* Reallocating buffer */
            scratch = (UINT8*)realloc(scratch, scratch_size);

            /* Compressing modified module */
            if(TianoCompress(decompressed, decompressed_size, scratch, &scratch_size) != EFI_SUCCESS)
            {
                *error_code = 7;
                goto error;
            }
        }
        else if(algorithm == ALG_LZMA)
        {
            UINT32 dict_size;
            UINT8 level;

            /* Determining buffer size for module compression */
            if(LzmaCompress(decompressed, decompressed_size, scratch, &scratch_size, 0, 0) != EFI_BUFFER_TOO_SMALL)
            {
                *error_code = 6;
                goto error;
            }
    
            /* Reallocating buffer */
            scratch = (UINT8*)realloc(scratch, scratch_size);

            /* Reading dictionary size */
            size2int(data + 1, &dict_size);

            /* Trying different compression levels */
            for(level = 5; level < 10; level++)
                if(LzmaCompress(decompressed, decompressed_size, scratch, &scratch_size, dict_size, level) == EFI_SUCCESS)
                {
                    grow = data_size > scratch_size ? data_size - scratch_size : scratch_size - data_size;
                    if(grow < 8 || -grow < 8)
                        break;
                }
        }
        
        /* Writing decompressed data to file */
        /*file = fopen("repacked.bin", "wb");
        fwrite(scratch, 1, scratch_size, file);
        fclose(file);*/

        /* Checking size */
        if (data_size < scratch_size)
        {
            BOOLEAN fits = TRUE;
            
            grow = scratch_size - data_size;
            end = module + PWRMGMT_DATA_OFFSET + data_size;
            /* Checking that there is free space after the module */
            while(grow--)
                if(*end-- != 0xFF)
                    fits = FALSE;
            /* Trying different patch */
            if(!fits)
                continue;
        }
        else if (data_size > scratch_size)
        {
            UINT8 freespace_length;

            grow = data_size - scratch_size;
            end = module + PWRMGMT_DATA_OFFSET + data_size - 1;
            while(grow--)
                *end-- = 0xFF;
            /* Checking that there is not too much space after modified module */
            *end++;
            for(freespace_length = 0; *end++ == 0xFF; freespace_length++);
            /* Trying different patch */
            if(freespace_length >= 8)
                continue;
        }

        patched = TRUE;
        break;
    }

    if(!patched)
    {
        *error_code = 8;
        goto error;
    }

    /* Writing new module sizes */
    if(!int2size(scratch_size + PWRMGMT_DATA_OFFSET, module_size_bytes))
    {
        *error_code = 1;
        goto error;
    }
    memcpy(module + MODULE_SIZE_OFFSET, module_size_bytes, 3);
    if(!int2size(scratch_size + PWRMGMT_COMPRESSED_DATA_OFFSET, module_size_bytes))
    {
        *error_code = 1;
        goto error;
    }
    memcpy(module + PWRMGMT_COMPRESSED_SIZE_OFFSET, module_size_bytes, 3);

    /* Replacing module */
    memcpy(module + PWRMGMT_DATA_OFFSET, scratch, scratch_size);

    /* Calculating checksums*/
    module[MODULE_DATA_CHECKSUM_OFFSET] = 0;
    module[MODULE_HEADER_CHECKSUM_OFFSET] = 0;

    /* Calculating header checksum*/
    if(!calculate_checksum(module, MODULE_DATA_CHECKSUM_START - 1, &header_checksum))
    {
        *error_code = 1;
        goto error;
    }
    module[MODULE_HEADER_CHECKSUM_OFFSET] = header_checksum;

    /* Calculating data checksum*/
    if(!calculate_checksum(module + MODULE_DATA_CHECKSUM_START, scratch_size + PWRMGMT_DATA_OFFSET - MODULE_DATA_CHECKSUM_START, &module_checksum))
    {
        *error_code = 1;
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

int patch_cpupei_module(UINT8* module, UINT8* error_code)
{
    UINT32 module_size;
    UINT8* string;

    /* Reading module size */
    if(!module  || !error_code || !size2int(module + MODULE_SIZE_OFFSET, &module_size))
    {
        *error_code = 1;
        return 0;
    }

    /* Searching for patch string */
    string = find_pattern(module, module_size, CPUPEI_PATCH_STRING, sizeof(CPUPEI_PATCH_STRING));
    if(!string)
    {
        *error_code = 2;
        return 0;
    }

    /* Patching */
    memcpy(string, CPUPEI_PATCHED_STRING, sizeof(CPUPEI_PATCHED_STRING));

    /* Patch complete */
    *error_code = 0;
    return 1;
}
