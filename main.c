#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "patch.h"

/* Program return codes */
#define ERR_OK                           0
#define ERR_ARGS                         1
#define ERR_INPUT_FILE                   2
#define ERR_OUTPUT_FILE                  3
#define ERR_MEMORY                       4
#define ERR_NO_MODULE                    5

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
    UINT8* module;
    UINT32 module_counter;
    UINT8 error_code;

    if(argc < 3)
    {
        printf("PMPatch v0.3.1\nThis program patches UEFI BIOS files\nto be compatible with MacOS X SpeedStep implementation\n\n"
            "Usage: PMPatch INFILE OUTFILE\n\n");
        return ERR_ARGS;
    }

    inputfile = argv[1]/*/"in.rom"*/;
    outputfile = argv[2]/*/"out.rom"*/;

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
        fprintf(stderr, "Can't allocate memory for buffer.\n");
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
        module = find_pattern(rest, rest_size, PWRMGMT_UUID, MODULE_UUID_LENGTH);
        if(module)
        {
            rest_size = filesize - (module - buffer);
            rest = module + 1;
            module_counter++;

            if(patch_powermanagement_module(module, &error_code))
                printf("PowerManagement module at %08X patched.\n", module - buffer);
            else
                printf("PowerManagement module at %08X not patched.\n%s\n", module - buffer, PATCH_PWRMGMT_ERROR_MESSAGES[error_code]);
        }
    }
    while(module);

    if(!module_counter)
    {
        printf("PowerManagement module not found.\n");
        
        /* Searching for CpuPei modules and patching them if found */
        module_counter = 0;
        rest = buffer;
        rest_size = filesize;
        do
        {
            module = find_pattern(rest, rest_size, CPUPEI_UUID, MODULE_UUID_LENGTH);
            if(module)
            {
                rest_size = filesize - (module - buffer);
                rest = module + 1;
                module_counter++;

                if(patch_cpupei_module(module, &error_code))
                    printf("CpuPei module at %08X patched.\n", module - buffer);
                else
                    printf("CpuPei module at %08X not patched.\n%s\n", module - buffer, PATCH_CPUPEI_ERROR_MESSAGES[error_code]);
            }
        }
        while(module);

        if(!module_counter)
        {
            printf("CpuPei module not found. Nothing to do.\n");
            return ERR_NO_MODULE;
        }
    }
    
    /* Creating output file*/
    file = fopen(outputfile, "wb");
    if (!file)
    {
        perror("Can't create output file.\n");
        return ERR_OUTPUT_FILE;
    }
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
