#pragma once
#include "Globals.h"

PVOID Query_Module(IN WCHAR* module, OUT PULONG ImageSize, OUT PULONG returnstatus);

ULONG Dump_Module(IN WCHAR* DumpFolder, IN WCHAR* DumpName, IN WCHAR* Module);



typedef struct _SYSTEM_MODULE_ENTRY
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

