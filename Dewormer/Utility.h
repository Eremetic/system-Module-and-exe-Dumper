#pragma once
#include "Globals.h"


bool Is_Driver_Loaded();

bool Ex_Cmp(LPWSTR input);

WCHAR* Proc_Comp(ULONG pPid);

bool Module_Cmp(LPWSTR input);

ULONG Suspend_Comp(WCHAR* pProc);

BOOL RSHasher(IN WCHAR* String1, IN WCHAR* String2);

BOOL Progress_Bar(int time, char symbol);




