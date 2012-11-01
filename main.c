/* PMPatch

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

#include "patch.h"

// Return codes 
#define ERR_OK                           0
#define ERR_ARGS                         1
#define ERR_INPUT_FILE                   2
#define ERR_OUTPUT_FILE                  3
#define ERR_MEMORY                       4
#define ERR_NO_MODULE                    5
#define ERR_PATCH                        6

int main(int argc, char* argv[])
{
    FILE* file;
    char* inputfile;
    char* outputfile;
    UINT8* buffer;
    INT32 filesize;
    INT32 read;
    UINT8 patch_result;

    printf("PMPatch 0.5.3\n");
    if(argc < 3)
    {
        printf("This program patches UEFI BIOS files\nto be compatible with MacOS X SpeedStep implementation\n\n"
            "Usage: PMPatch INFILE OUTFILE\n\n");
        return ERR_ARGS;
    }

    inputfile = argv[1];
    outputfile = argv[2];

    // Opening input file 
    file = fopen(inputfile, "rb");
    if (!file)
    {
        perror("Can't open input file.\n");
        return ERR_INPUT_FILE;
    }

    // Determining file size 
    fseek(file, 0, SEEK_END);
    filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocating memory for buffer 
    buffer = (UINT8*)malloc(filesize);
    if (!buffer)
    {
        fprintf(stderr, "Can't allocate memory for buffer.\n");
        return ERR_MEMORY;
    }

    // Reading whole file to buffer 
    read = fread((void*)buffer, sizeof(char), filesize, file);
    if (read != filesize)
    {
        perror("Can't read input file.\n");
        return ERR_INPUT_FILE;
    }

    // Closing input file 
    fclose(file);

    // Patching BIOS 
    patch_result = patch_bios(buffer, filesize);
    if(patch_result)
        return ERR_PATCH;

    // Creating output file
    file = fopen(outputfile, "wb");
    if (!file)
    {
        perror("Can't create output file.\n");
        return ERR_OUTPUT_FILE;
    }

    // Writing modified BIOS file
    if(fwrite(buffer, sizeof(char), filesize, file) != filesize)
    {
        perror("Can't write output file.\n");
        return ERR_OUTPUT_FILE;
    }

    // Closing output file 
    fclose(file);

    return ERR_OK;
}
