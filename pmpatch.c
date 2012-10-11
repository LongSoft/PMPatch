#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "EDK2/Compress.h"
#include "EDK2/Decompress.h"

/* Definitions */
/* Return codes */
#define ERR_OK                           0
#define ERR_ARGS                         1
#define ERR_INPUT_FILE                   2
#define ERR_MEMORY                       3
#define ERR_NO_MODULE                    4

/* Module UUIDs */
const unsigned char PWRMGMT_UUID[] =     {'\x70','\x39','\x78','\x8C',
                                          '\x2A','\xF0','\x4D','\x4A',
                                          '\xAF','\x09','\x87','\x97',
                                          '\xA5','\x1E','\xEC','\x8D'};
const unsigned char CPUPEI_UUID[] =      {'\xA9','\xAF','\xB5','\x2B',
                                          '\x33','\xFF','\x7B','\x41',
                                          '\x84','\x97','\xCB','\x77',
                                          '\x3C','\x2B','\x93','\xBF'};
/* Patch strings */
const unsigned char PATCH_STRING[] =     {'\x75','\x08','\x0F','\xBA',
                                          '\xE8','\x0F','\x89','\x44',
                                          '\x24','\x30'};
const unsigned char PATCHED_STRING[] =   {'\xEB','\x08','\x0F','\xBA',
                                          '\xE8','\x0F','\x89','\x44',
                                          '\x24','\x30'};
/* Data offsets and sizes*/
#define MODULE_UUID_LENGTH               16
#define MODULE_SIZE_OFFSET               20
#define MODULE_COMPRESSED_SIZE_OFFSET    172
#define MODULE_COMPRESSED_DATA_OFFSET    9
#define MODULE_DATA_OFFSET               181
#define MODULE_HEADER_CHECKSUM_OFFSET    16
#define MODULE_DATA_CHECKSUM_START       24
#define MODULE_DATA_CHECKSUM_OFFSET      17

/* Implementation of GNU memmem function using Boyer-Moore-Horspool algorithm */
/* Finds pattern in string */
/* Returns pointer to the first symbol of found pattern, or NULL if not found */
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

/* Calculates 2's complement 8-bit checksum of data from data[0] to data[length-1] and stores it to *checksum */
/* Returns 1 on success or 0 on error */
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

/* Converst UINT32 to 3 bytes in reversed order. */
/* Returns 1 on success or 0 on error */
int int2size(UINT32 size, UINT8* module_size)
{
    if(!module_size)
        return 0;
    module_size[2] = (UINT8) (((size) >> 16));
    module_size[1] = (UINT8) (((size) >>  8));
    module_size[0] = (UINT8) (((size)      ));
    return 1;
}

/* Converts 3 bytes in reversed order to UINT32. */
/* Returns 1 on success or 0 on error */
int size2int(UINT8* module_size, UINT32* size)
{
    if(!module_size || !size)
        return 0;

    *size = (module_size[2] << 16) + 
            (module_size[1] << 8) + 
             module_size[0];
}

/* Patches module */
/* Returns 1 on success or 0 on error */
int patch_module(UINT8* module)
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
    if(!module || !size2int(module + MODULE_SIZE_OFFSET, &module_size))
        return 0;
    
    /* Setting pointer and size to module body */
    data = module + MODULE_DATA_OFFSET;
    data_size = module_size - MODULE_DATA_OFFSET;

    /* Checking file compression algorithm to be Tiano and receiving buffers sizes for module extraction */
    if(!EfiGetInfo(data, data_size, &decompressed_size, &scratch_size) == EFI_SUCCESS)
        return 0;

    /* Allocating memory for buffers */
    decompressed = (UINT8*)malloc(decompressed_size);
    scratch = (UINT8*)malloc(scratch_size);
    if(!decompressed || !scratch)
        goto error;

    /* Trying to unpack module*/
    if(TianoDecompress(data, data_size, decompressed, decompressed_size, scratch, scratch_size) != EFI_SUCCESS)
        goto error;

    /*Searching for bytes to patch */
    string = find_pattern(decompressed, decompressed_size, PATCH_STRING, sizeof(PATCH_STRING));
    if(!string)
        goto error;

    /* Patching unpacked module*/
    memcpy(string, PATCHED_STRING, sizeof(PATCHED_STRING));
    
    /* Determining buffer size for compressed module */
    scratch_size = 0;
    if(TianoCompress(decompressed, decompressed_size, scratch, &scratch_size) != EFI_BUFFER_TOO_SMALL)
        goto error;
    
    /* Reallocating buffer*/
    scratch = (UINT8*)realloc(scratch, scratch_size);

    /* Compressing modified module*/
    if(TianoCompress(decompressed, decompressed_size, scratch, &scratch_size) != EFI_SUCCESS)
        goto error;
    
    /* Resizing module*/
    if (data_size < scratch_size)
    {
        grow = scratch_size - data_size;
        end = module + MODULE_DATA_OFFSET + data_size;
        /* Checking that there are free space after the module*/
        while(grow--)
            if(*end-- != (UINT8)'\xFF')
                goto error; /* TODO: Mark module as deleted and insert a new one at the end of volume */
    }
    else if (data_size > scratch_size)
    {
        grow = data_size - scratch_size;
        end = module + MODULE_DATA_OFFSET + scratch_size;
        while(grow--)
            *end-- = (UINT8)'\xFF'; 
    }

    /* Writing new module sizes */
    if(!int2size(scratch_size + MODULE_DATA_OFFSET, module_size_bytes))
        goto error;
    memcpy(module + MODULE_SIZE_OFFSET, module_size_bytes, 3);
    if(!int2size(scratch_size + MODULE_COMPRESSED_DATA_OFFSET, module_size_bytes))
        goto error;
    memcpy(module + MODULE_COMPRESSED_SIZE_OFFSET, module_size_bytes, 3);

    /* Writing new compressed data*/
    memcpy(module + MODULE_DATA_OFFSET, scratch, scratch_size);

    /* Calculating checksums*/
    module[MODULE_DATA_CHECKSUM_OFFSET] = 0;
    module[MODULE_HEADER_CHECKSUM_OFFSET] = 0;

    /* Calculating data checksum*/
    if(!calculate_checksum(module, MODULE_DATA_CHECKSUM_START - 1, &header_checksum))
        goto error;
    module[MODULE_HEADER_CHECKSUM_OFFSET] = header_checksum;

    /* Calculating header checksum*/
    if(!calculate_checksum(module + MODULE_DATA_CHECKSUM_START, scratch_size + MODULE_DATA_OFFSET - MODULE_DATA_CHECKSUM_START, &module_checksum))
        goto error;
    module[MODULE_DATA_CHECKSUM_OFFSET] = module_checksum;
    
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

int main(int argc, char* argv[])
{
    FILE* file;
    char* inputfile;
    char* outputfile;
    UINT8* buffer;
    INT32 filesize;
    INT32 read;
    UINT8* rest;
    INT32 rest_size;
    UINT8* pwrmgmt;
    UINT8* cpupei;
    UINT32 module_counter;

    if(argc < 3)
    {
        printf("PMPatch v0.1\nThis program patches ASUS BIOS files\nto be compatible with MacOS X SpeedStep implementation\n\n"
            "Usage: MPatcher INFILE OUTFILE\n\n");
        return ERR_ARGS;
    }

    inputfile = argv[1];
    outputfile = argv[2];

     /* Opening input file */
    file = fopen(inputfile, "rb");
    if (!file)
    {
        perror("Can't open input file.\n");
        return ERR_INPUT_FILE;
    }

    /* Determining file size */
    fseek(file, 0, SEEK_END);
    filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* Allocating memory for buffer */
    buffer = (UINT8*)malloc(filesize);
    if (!buffer)
    {
        fprintf(stderr, "Can't allocate memory for input buffer.\n");
        return ERR_MEMORY;
    }

    /* Reading whole file to buffer */
    read = fread((void*)buffer, sizeof(char), filesize, file);
    if (read != filesize)
    {
        perror("Can't read input file.\n");
        return ERR_INPUT_FILE;
    }

    /* Closing input file */
    fclose(file);

    /* Searching for PowerManagement modules and patching them if found */
    module_counter = 0;
    rest = buffer;
    rest_size = filesize;
    do
    {
        pwrmgmt = find_pattern(rest, rest_size, PWRMGMT_UUID, MODULE_UUID_LENGTH);
        if(pwrmgmt)
        {
            if(patch_module(pwrmgmt))
                printf("PowerManagement module at %08X patched.\n", pwrmgmt - buffer);
            else
                printf("PowerManagement module at %08X not patched.\n", pwrmgmt - buffer);
            rest_size = filesize - (pwrmgmt - buffer);
            rest = pwrmgmt + 1;
            module_counter++;
        }
    }
    while(pwrmgmt);

    if(!module_counter)
    {
        printf("PowerManagement module not found. Nothing to do.\n");
        return ERR_NO_MODULE;
    }
    
    /* Creating output file*/
    file = fopen(outputfile, "wb");
    
    /* Writing modified BIOS file*/
    if(fwrite(buffer, sizeof(char), filesize, file) != filesize)
    {
        perror("Can't write input file.\n");
        return ERR_INPUT_FILE;
    }

    /* Closing output file */
    fclose(file);

    /* Freeing buffer */
    free(buffer);
    
    return ERR_OK;
}
