#ifndef __MODULE_H__
#define __MODULE_H__

#include <stdio.h>
#include <stdlib.h>
#include "EDK2/Compress.h"
#include "EDK2/Decompress.h"

/* Module UUIDs */
extern const UINT8 PWRMGMT_UUID[];
extern const UINT8 CPUPEI_UUID[];
extern const UINT8 VOLUME_TOP_UUID[];

/* Patch strings */
extern const UINT8 PATCH_STRING[];
extern const UINT8 PATCHED_STRING[];

/* Data offsets and sizes*/
#define MODULE_UUID_LENGTH               16
#define MODULE_STATE_OFFSET              23
#define MODULE_SIZE_OFFSET               20
#define MODULE_COMPRESSED_SIZE_OFFSET    172
#define MODULE_COMPRESSED_DATA_OFFSET    9
#define MODULE_DATA_OFFSET               181
#define MODULE_HEADER_CHECKSUM_OFFSET    16
#define MODULE_DATA_CHECKSUM_OFFSET      17
#define MODULE_DATA_CHECKSUM_START       24

/* Error messages array - index of that array is an error code */
extern const UINT8* PATCH_MODULE_ERROR_MESSAGES[];

/* Implementation of GNU memmem function using Boyer-Moore-Horspool algorithm */
/* Finds pattern in string */
/* Returns pointer to the first symbol of found pattern, or NULL if not found */
UINT8* find_pattern(UINT8* string, UINT32 slen, const UINT8* pattern, UINT32 plen);

/* Calculates 2's complement 8-bit checksum of data from data[0] to data[length-1] and stores it to *checksum */
/* Returns 1 on success or 0 on error */
int calculate_checksum(UINT8* data, UINT32 length, UINT8* checksum);

/* Converts UINT32 to 3 bytes in reversed order. */
/* Returns 1 on success or 0 on error */
int int2size(UINT32 size, UINT8* module_size);

/* Converts 3 bytes in reversed order to UINT32. */
/* Returns 1 on success or 0 on error */
int size2int(UINT8* module_size, UINT32* size);

/* Patches module */
/* Returns 1 on success or 0 on error and error_code is set to non-zero */
int patch_module(UINT8* module, UINT8* error_code);

#endif /* __MODULE_H__ */
