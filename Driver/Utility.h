#pragma once
#include "Globals.h"


BOOL RSHasher(IN PWCHAR String1, IN PWCHAR String2);

ULONG PE_Check(IN PVOID BaseAddr);

ULONG Fix_Headers(IN LPVOID BaseAddr);
