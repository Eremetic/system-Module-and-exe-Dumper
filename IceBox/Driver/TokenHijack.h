#pragma once
#include "Globals.h"


ULONG Hijack_Token(INT64 Pid);


/// token hijack structs definitions and misc
typedef struct _EX_FAST_REF
{
	union _T
	{
		PVOID Object;
		ULONG RefCnt : 3;
		ULONG Value;
	}T;
} EX_FAST_REF, * PEX_FAST_REF;



#define _SYS 4

#define STATUS_NO_TOKEN_ADDRESS	   0x007a
#define STATUS_FAILED_TOKEN_SWAP	0x07e
#define STATUS_FAILED_EPROCESS     0x0397