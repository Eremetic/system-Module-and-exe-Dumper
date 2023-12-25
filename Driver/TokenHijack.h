#pragma once
#include "Globals.h"


ULONG Hijack_Token(IN WCHAR* TargetProc, IN WCHAR* OurProc);


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




