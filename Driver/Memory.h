#include "Globals.h"



PVOID Process_Base(IN PEPROCESS process, OUT PULONG status);

ULONG_PTR Process_CR3(IN PEPROCESS process, OUT PULONG status);

PEPROCESS Process(IN WCHAR* ProcName);

ULONG_PTR VtoP(IN VIRTUAL_ADDRESS Linear, IN ULONG_PTR CR3, OUT PULONG status);

VOID Read_Process_Memory(
	_Inout_ PUCHAR pBuffer,
	IN VIRTUAL_ADDRESS linear, 
	IN SIZE_T length, 
	IN ULONG_PTR DirectoryTableBase, 
	OUT PULONG status);

VOID Map_Physical_2_Virtual(
	OUT PUCHAR* VirtualAddress,
	IN ULONG_PTR physicalAddress,
	IN ULONG_PTR length,
	OUT PULONG status);

VOID Unmap_Physical_From_Virtual(IN PUCHAR virtualAddress, OUT PULONG status);

VOID Read_Mapped_Data(_Inout_ PVOID pBuffer, IN PUCHAR virtualAddress, IN SIZE_T length, OUT PULONG status);

ULONG Hijack_Token(IN WCHAR* TargetProc, IN WCHAR* OurProc);



/// token hijack struct 
typedef struct _EX_FAST_REF
{
	union _T
	{
		PVOID Object;
		ULONG RefCnt : 3;
		ULONG Value;
	}T;
} EX_FAST_REF, * PEX_FAST_REF;



/// zwquery 
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;



/// physical pages
typedef union _PML4_ENTRY
{
	ULONG_PTR value;

	struct
	{
		ULONG_PTR Valid : 1;
		ULONG_PTR Write : 1;
		ULONG_PTR Owner : 1;
		ULONG_PTR WriteThrough : 1;
		ULONG_PTR CacheDisable : 1;
		ULONG_PTR Accessed : 1;
		ULONG_PTR Dirty : 1;
		ULONG_PTR LargePage : 1;
		ULONG_PTR Global : 1;
		ULONG_PTR software_CopyOnWrite : 1;
		ULONG_PTR software_Prototype : 1;
		ULONG_PTR software_Write : 1;
		ULONG_PTR PageFrameNumber : 37;
		ULONG_PTR reserved0 : 3;
		ULONG_PTR reserved1 : 11;
		ULONG_PTR NoExecute : 1;
	}Bit;
}PML4E, * PPML4E;

typedef struct _PML4
{
	ULONG_PTR entry_Ptr;
	PML4E Entry;
}PML4;




typedef union _PDP_ENTRY
{
	ULONG_PTR value;

	struct
	{
		ULONG_PTR Valid : 1;
		ULONG_PTR Write : 1;
		ULONG_PTR Owner : 1;
		ULONG_PTR WriteThrough : 1;
		ULONG_PTR CacheDisable : 1;
		ULONG_PTR Accessed : 1;
		ULONG_PTR Dirty : 1;
		ULONG_PTR LargePage : 1;
		ULONG_PTR Global : 1;
		ULONG_PTR software_CopyOnWrite : 1;
		ULONG_PTR software_Prototype : 1;
		ULONG_PTR software_Write : 1;
		ULONG_PTR PageFrameNumber : 37;
		ULONG_PTR reserved0 : 3;
		ULONG_PTR reserved1 : 11;
		ULONG_PTR NoExecute : 1;
	}Bit;
}PDPE, * PPDPE;


/// large page PDP
typedef union _1GB_PDP_ENTRY
{
    ULONG_PTR value;
 
	struct
	{
		ULONG_PTR Valid : 1;
		ULONG_PTR Write : 1;
		ULONG_PTR Owner : 1;
		ULONG_PTR WriteThrough : 1;
		ULONG_PTR CacheDisable : 1;
		ULONG_PTR Accessed : 1;
		ULONG_PTR Dirty : 1;
		ULONG_PTR LargePage : 1;
		ULONG_PTR Global : 1;
		ULONG_PTR software_CopyOnWrite : 1;
		ULONG_PTR software_Prototype : 1;
		ULONG_PTR software_Write : 1;
		ULONG_PTR Pat : 1;
		ULONG_PTR Reserved : 17;
		ULONG_PTR PageFrameNumber : 19;
		ULONG_PTR reserved0 : 3;
		ULONG_PTR reserved1 : 7;
		ULONG_PTR Protect : 4;
		ULONG_PTR NoExecute : 1;
	}Bit;
} LRG_PDPE, * PLRG_PDPE;

typedef struct _PDP
{
	ULONG_PTR entry_Ptr;
	PDPE Entry;
	LRG_PDPE lrg_Entry;
}PDP;



typedef union _PD_ENTRY
{
	ULONG_PTR value;

	struct
	{
		ULONG_PTR Valid : 1;
		ULONG_PTR Write : 1;
		ULONG_PTR Owner : 1;
		ULONG_PTR WriteThrough : 1;
		ULONG_PTR CacheDisable : 1;
		ULONG_PTR Accessed : 1;
		ULONG_PTR Dirty : 1;
		ULONG_PTR LargePage : 1;
		ULONG_PTR Global : 1;
		ULONG_PTR software_CopyOnWrite : 1;
		ULONG_PTR software_Prototype : 1;
		ULONG_PTR software_Write : 1;
		ULONG_PTR PageFrameNumber : 37;
		ULONG_PTR reserved0 : 3;
		ULONG_PTR reserved1 : 11;
		ULONG_PTR NoExecute : 1;
	}Bit;
}PDE, * PPDE;


/// large page PD
typedef union _4MB_PDE
{
    ULONG_PTR value;
	
	struct
	{
		ULONG_PTR Valid : 1;
		ULONG_PTR Write : 1;
		ULONG_PTR Owner : 1;
		ULONG_PTR WriteThrough : 1;
		ULONG_PTR CacheDisable : 1;
		ULONG_PTR Accessed : 1;
		ULONG_PTR Dirty : 1;
		ULONG_PTR LargePage : 1;
		ULONG_PTR Global : 1;
		ULONG_PTR software_CopyOnWrite : 1;
		ULONG_PTR software_Prototype : 1;
		ULONG_PTR software_Write : 1;
		ULONG_PTR Pat : 1;
		ULONG_PTR Reserved0 : 8;
		ULONG_PTR PageFrameNumber : 28;
		ULONG_PTR reserved1 : 3;
		ULONG_PTR reserved2 : 7;
		ULONG_PTR Protect : 4;
		ULONG_PTR NoExecute : 1;
	}Bit;
} LRG_PDE, * PLRG_PDE;

typedef struct _PD
{
	ULONG_PTR entry_Ptr;
	PDE Entry;
	LRG_PDE lrg_Entry;
}PD;



typedef union _PT_ENTRY
{
	ULONG_PTR value;

	struct
	{
		ULONG_PTR Valid : 1;
		ULONG_PTR Write : 1;
		ULONG_PTR Owner : 1;
		ULONG_PTR WriteThrough : 1;
		ULONG_PTR CacheDisable : 1;
		ULONG_PTR Accessed : 1;
		ULONG_PTR Dirty : 1;
		ULONG_PTR Pat : 1;
		ULONG_PTR Global : 1;
		ULONG_PTR software_CopyOnWrite : 1;
		ULONG_PTR software_Prototype : 1;
		ULONG_PTR software_Write : 1;
		ULONG_PTR PageFrameNumber : 37;
		ULONG_PTR reserved1 : 3;
		ULONG_PTR reserved2 : 7;
		ULONG_PTR Protect : 4;
		ULONG_PTR NoExecute : 1;
	}Bit;
}PTE, * PPTE;

typedef struct _PT
{
	ULONG_PTR entry_Ptr;
	PTE Entry;
}PT;



///for debug
typedef union _CR3
{
	ULONG_PTR value;

	struct
	{
		ULONG_PTR Reserved0 : 3;
		ULONG_PTR WriteThrough : 1;
		ULONG_PTR CacheDisable : 1;
		ULONG_PTR Reserved1 : 7;
		ULONG_PTR Pml4 : 37;
		ULONG_PTR Reserved2 : 15;
	}Bits;
}CR3, * PCR3;
