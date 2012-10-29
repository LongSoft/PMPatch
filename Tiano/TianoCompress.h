/** @file

Copyright (c) 2004 - 2008, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials                          
are licensed and made available under the terms and conditions of the BSD License         
which accompanies this distribution.  The full text of the license may be found at        
http://opensource.org/licenses/bsd-license.php                                            
                                                                                          
THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

Module Name:

  TianoCompress.h

Abstract:

  Header file for compression routine.
  
**/

#ifndef _TIANOCOMPRESS_H_
#define _TIANOCOMPRESS_H_

#include <string.h>
#include <stdlib.h>

#include "../Common/UefiBaseTypes.h"

/*++

Routine Description:

  Tiano compression routine.

--*/
EFI_STATUS
TianoCompress (
  IN      UINT8   *SrcBuffer,
  IN      UINT32  SrcSize,
  IN      UINT8   *DstBuffer,
  IN OUT  UINT32  *DstSize
  )
;

#endif
