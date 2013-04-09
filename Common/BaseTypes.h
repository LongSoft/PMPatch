/* Processor or Compiler specific defines for all supported processors.

This file is stand alone self consistent set of definitions. 

Copyright (c) 2006, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials                          
are licensed and made available under the terms and conditions of the BSD License         
which accompanies this distribution.  The full text of the license may be found at        
http://opensource.org/licenses/bsd-license.php                                            

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

File Name:  BaseTypes.h

*/

#ifndef __BASE_TYPES_H__
#define __BASE_TYPES_H__

//
// Include processor specific binding
//
#include "ProcessorBind.h"
#include <stdarg.h>

#define CONST     const
#define STATIC    static
#define VOID      void

#ifndef TRUE
#define TRUE  ((BOOLEAN)(1==1))
#endif

#ifndef FALSE
#define FALSE ((BOOLEAN)(0==1))
#endif

#ifndef NULL
#define NULL  ((VOID *) 0)
#endif

#define ERR_SUCCESS               0
#define ERR_INVALID_PARAMETER     1
#define ERR_BUFFER_TOO_SMALL      2
#define ERR_OUT_OF_RESOURCES      3
#define ERR_OUT_OF_MEMORY         4
#define ERR_NOT_PATCHED           5
#define ERR_FILE_OPEN             6
#define ERR_FILE_READ             7
#define ERR_FILE_WRITE            8

#include <assert.h>
#define ASSERT(x) assert(x)

#endif
