/* Patch Header 

  Copyright (c) 2012, Nikolaj Schlej. All rights reserved.
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#ifndef __PATCH_H__
#define __PATCH_H__

#include "Common/UefiBaseTypes.h"

// Patches BIOS 
BOOLEAN patch_bios(UINT8* bios, UINT32 size);

#endif // __PATCH_H__ 
