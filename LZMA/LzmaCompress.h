/* LZMA Compress Header

  Copyright (c) 2012, Nikolaj Schlej. All rights reserved.
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#ifndef __LZMACOMPRESS_H__
#define __LZMACOMPRESS_H__

#include "../Common/UefiBaseTypes.h"

#define LZMA_DICTIONARY_SIZE 0x800000

EFI_STATUS
EFIAPI
LzmaCompress (
  IN CONST VOID  *Source,
  IN UINTN       SourceSize,
  IN OUT VOID    *Destination,
  IN OUT UINTN   *DestinationSize
  );

#endif