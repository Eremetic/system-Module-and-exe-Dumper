#pragma once
#include "Globals.h"


#define IMAGE_FIRST_SECTION(p_inh)                       \
	((PIMAGE_SECTION_HEADER)((ULONG_PTR)(p_inh)+			\
	 FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +		\
		((p_inh))->FileHeader.SizeOfOptionalHeader))

ULONG Dump_Process(IN WCHAR* TargetProc, IN WCHAR* DumpFolder, IN WCHAR* DumpName);

ULONG Fix_Pe(IN PVOID baseAddr);

//PIMPORT_INFO Import_IAT(IN ULONG64 DTblBase, IN PVOID baseAddr, OUT PULONG returnstatus, PULONG status);

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


