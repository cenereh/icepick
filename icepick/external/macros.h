#pragma once
#include <Windows.h>

/*
* Multiple definitions under the same comment are just for syntax sugar, to make casting more "understandable"
*/

// Allows to calculate pointers as DWORD values
#define _PTR(ptr)		DWORD_PTR(ptr)

// Directly manipulates WORD values in raw memory (2 bytes)
#define _RAWWORD(ptr)	*(WORD*)(ptr)

// Directly manipulates DWORD values in raw memory (4 bytes)
#define _RAWDWR(ptr)	*(DWORD*)(ptr)

// Directly manipulates DWORD64 values in raw memory (8 bytes)
#define _RAWDWR_64(ptr)	*(DWORD_PTR*)(ptr)

// Casts a value to a 4 bytes DWORD
#define _DW(val)		DWORD(val)
#define _UL(val)		ULONG(val)

// Casts a value to a 8 bytes DWORD
#define _DW_64(val)		DWORD64(val)
#define _UL_64(val)		ULONG_PTR(val)

// Casts a value to a void* (or HANDLE) value
#define _VPTR(val)		(void*)(val)
#define _H(val)			(HANDLE)(val)

// Casts a value to a ULONG* value
#define _ULPTR(val)		(ULONG*)(val)

// Converts a string to an integer value (yes std::atoi exists but this is better because no import table shenanigans)
#define PC_STR_TOINT(X)	((((X) >= ('0')) && ((X) <= ('9'))) ? ((X) - ('0')) : (X))