/* Tiano Decompress Header

Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.
This program and the accompanying materials                          
are licensed and made available under the terms and conditions of the BSD License         
which accompanies this distribution.  The full text of the license may be found at        
http://opensource.org/licenses/bsd-license.php                                            
                                                                                          
THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
WITHWARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

Module Name:
  
  TianoDecompress.h

Abstract:

  Header file for compression routine
  
*/

#ifndef _TIANODECOMPRESS_H
#define _TIANODECOMPRESS_H

#include "../Common/BaseTypes.h"

INT32
TianoGetInfo (
  VOID    *Source,
  UINT32  SrcSize,
  UINT32  *DstSize,
  UINT32  *ScratchSize
  );
/*

Routine Description:

  The implementation Tiano Decompress GetInfo().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  DstSize     - The size of destination buffer.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - The size of destination buffer and the size of scratch buffer are successull retrieved.
  EFI_INVALID_PARAMETER - The source data is corrupted

*/

INT32
TianoDecompress (
  VOID    *Source,
  UINT32  SrcSize,
  VOID    *Destination,
  UINT32  DstSize,
  VOID    *Scratch,
  UINT32  ScratchSize
  );
/*

Routine Description:

  The implementation of Tiano Decompress().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  Destination - The destination buffer to store the decompressed data
  DstSize     - The size of destination buffer.
  Scratch     - The buffer used internally by the decompress routine. This  buffer is needed to store intermediate data.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - Decompression is successfull
  EFI_INVALID_PARAMETER - The source data is corrupted

*/
#endif
