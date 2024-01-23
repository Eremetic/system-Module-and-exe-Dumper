#pragma once
#include "Globals.h"

#define ToWstring(x)  Char_2_Wchar(x)


bool Is_Driver_Loaded();

bool Ex_Cmp(LPWSTR input);

wchar_t* Char_2_Wchar(char* input);

WCHAR* Proc_Comp(ULONG pPid);

bool Module_Cmp(LPWSTR input);

ULONG Suspend_Comp(WCHAR* pProc);

BOOL RSHasher(IN WCHAR* String1, IN WCHAR* String2);

BOOL Progress_Bar(int time, char symbol);




