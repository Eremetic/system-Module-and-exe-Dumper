#pragma once
#include "Globals.h"


BOOL RSHasher(IN PWCHAR String1, IN PWCHAR String2);

ULONG PE_Check(IN PVOID BaseAddr);

ULONG Fix_Headers(IN LPVOID BaseAddr);

ULONG AlignValue(ULONG value, ULONG alignment);


#define IMAGE_FIRST_SECTION(p_inh)                       \
	((PIMAGE_SECTION_HEADER)((ULONG_PTR)(p_inh)+			\
	 FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +		\
		((p_inh))->FileHeader.SizeOfOptionalHeader))