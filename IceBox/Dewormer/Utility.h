#pragma once
#include "Globals.h"

bool Is_Driver_Loaded();

bool Ex_Cmp(LPWSTR input);

WCHAR* Suspend_Comp(ULONG pPid);

bool Module_Cmp(LPWSTR input);

ULONG Suspend_Comp(WCHAR* pProc);

BOOL Admin_Check();

static int Num_Gen();

static UINT32 RS_Sub(UINT32 Value, UINT Count);

BOOL RSHasher(IN PWCHAR String1, IN PWCHAR String2);