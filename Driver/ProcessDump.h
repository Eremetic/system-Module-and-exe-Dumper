#pragma once
#include "Globals.h"



///Adv Dump
UNICODE_STRING AdvDmpTarget;
UNICODE_STRING AvdDumpFldr;
UNICODE_STRING AvdDumpName;


ULONG Dump_Process(IN WCHAR* TargetProc, IN WCHAR* DumpFolder, IN WCHAR* DumpName);

//void Advanced_Process_Dump(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);


/// structs
enum _DRX
{
    Dr0 = 0,
    Dr1 = 1,
    Dr2 = 2,
    Dr3 = 3,
};


///Undocumented thread functions
typedef NTSTATUS (__stdcall* fnPsSuspendProcess)(
    IN HANDLE        hProcess
);


typedef NTSTATUS (__stdcall* PsResumeProcess)(
    IN HANDLE        hProcess
);



typedef NTSTATUS(__stdcall* PsGetContextThread)(
    IN HANDLE        ThreadHandle,
    OUT PCONTEXT     pContext
);


typedef NTSTATUS(__stdcall* PsSetContextThread)(
    IN HANDLE         ThreadHandle,
    IN PCONTEXT       Context
);


