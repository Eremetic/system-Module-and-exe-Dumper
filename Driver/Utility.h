#pragma once
#include "Globals.h"


BOOL RSHasher(IN PWCHAR String1, IN PWCHAR String2);

ULONG PE_Check(IN PVOID BaseAddr);

ULONG Fix_Headers(IN LPVOID BaseAddr);

BOOL Attach_To_Pocess(_Inout_ PEPROCESS process);

BOOL Detach_From_Process(_Inout_ PEPROCESS process);

