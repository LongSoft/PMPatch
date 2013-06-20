/* PMPatch

  Copyright (c) 2012, Nikolaj Schlej. All rights reserved.
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

int main(int argc, char* argv[])
{
    FILE* file;
    char* inputfile;
    char* outputfile;
    UINT8* buffer;
    size_t filesize;
    size_t read;

    printf("PMPatch 0.5.13\n");
    if(argc < 3)
    {
        printf("This program patches UEFI BIOS files\nto be compatible with Mac OS X SpeedStep implementation\n\n"
            "Usage: PMPatch INFILE OUTFILE\n\n");
        return ERR_INVALID_PARAMETER;
    }

    inputfile = argv[1];
    outputfile = argv[2];

    // Opening input file 
    file = fopen(inputfile, "rb");
    if (!file)
    {
        perror("Can't open input file.\n");
        return ERR_FILE_OPEN;
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
        return ERR_OUT_OF_MEMORY;
    }

    // Reading whole file to buffer 
    read = fread((void*)buffer, sizeof(char), filesize, file);
    if (read != filesize)
    {
        perror("Can't read input file.\n");
        return ERR_FILE_READ;
    }

    // Closing input file 
    fclose(file);

    // Patching BIOS 
    if(!patch_bios(buffer, (UINT32)filesize))
        return ERR_NOT_PATCHED;
    

    // Creating output file
    file = fopen(outputfile, "wb");
    if (!file)
    {
        perror("Can't create output file.\n");
        return ERR_FILE_OPEN;
    }

    // Writing modified BIOS file
    if(fwrite(buffer, sizeof(char), filesize, file) != filesize)
    {
        perror("Can't write output file.\n");
        return ERR_FILE_WRITE;
    }

    // Closing output file 
    fclose(file);
    printf("Output file generated.\n");

    return ERR_SUCCESS;
}
