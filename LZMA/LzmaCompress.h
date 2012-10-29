#ifndef __LZMACOMPRESS_H__
#define __LZMACOMPRESS_H__

#include "../Common/UefiBaseTypes.h"

#include <assert.h>
#define ASSERT(x) assert(x)

#define SIZE_64KB 0x00010000
#define SCRATCH_BUFFER_REQUEST_SIZE SIZE_64KB

RETURN_STATUS
EFIAPI
LzmaCompress (
  IN CONST VOID  *Source,
  IN UINTN       SourceSize,
  IN OUT VOID    *Destination,
  IN OUT UINTN   *DestinationSize,
  IN UINTN       DictSize,
  IN UINT8       CompressionLevel
  );

#endif