#pragma once
#include <Windows.h>
#include <string>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <psapi.h>
#include <filesystem>
#include <winternl.h>




/// encryption
constexpr ULONG ExprXorKey(
    VOID
) {
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
}

constexpr ULONG ObfXorKey = ExprXorKey();


///pvoid cast
#define C_PTR( x ) ((void*) x )


/// Driver Interface stuff
#define IOCTL_DUMP_MODULE		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1728, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_DUMP_PROCESS		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1730, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_HIJACK_TOKEN		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1732, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_ADV_DUMP_PROCESS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1734, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)



typedef struct _DUMP_MODULE
{
	WCHAR* DumpFolder;
	WCHAR* DumpName;
	WCHAR* ModuleName;
	ULONG Response;
} DUMP_MODULE, * PDUMP_MODULE;

typedef struct _DUMP_PROCESS
{
	WCHAR* ProcName;
	WCHAR* DumpFolder;
	WCHAR* DumpName;
	ULONG Response;
} DUMP_PROCESS, * PDUMP_PROCESS;

typedef struct _HIJACK_TOKEN
{
	WCHAR* TargetProc;
	WCHAR* OurProc;
	ULONG Response;
}HIJACK_TOKEN, * PHIJACK_TOKEN;


typedef struct _ADV_DUMP_PROCESS
{
	WCHAR* ProcName;
	WCHAR* DumpFolder;
	WCHAR* DumpName;
} ADV_DUMP_PROCESS, * PADV_DUMP_PROCESS;


/// driver error codes
enum ErrorCodes
{
	Success = 0x00000000,
	InValidDriverHandle = 0x0111999,
	FailedBaseAddress = 0x0f34,
	FailedToAllocateBuffer = 0x0f34f5,
	MmCopyMemoryFailed = 0x01710ff,
	FailedToReadMemory = 0x0f75171,
	FailedEmagicCheck = 0x0f3171,
	FailedNtSigCheck = 0x0f1726,
	FailedToCreateDirectory = 0x0ffff,
	FailedToCreateFile = 0x0fff1,
	FailedToWriteDump = 0x0f7171,
	FailedFirstSection = 0x0f4250,
	FailedUlonglong2Ulong = 0x0f101017,
	FailedToFindTokenAddress = 0x007a,
	FailedToSwapToken = 0x07e,
	FailedToGetTargetEprocess = 0x0397,
	FailedToGetProcID = 0x0f918,
	FailedZwQuery = 0x0ff21716,
	FailedToGetImageSize = 0x0ff759,
	FailedPml4e = 0xff91474,
	FailedPdpte = 0xff87361,
	FailedLrgPdpte = 0xff873611,
	FailedPde = 0xff772251,
	FailedLrgPde = 0xff772222,
	FailedPte = 0xff00EA1,
	FailedToOpenSection = 0xee4321,
	FailedToRefHnadle = 0xef8698,
	FailedHal = 0xea9921,
	FailedToMapSection = 0xeb6270,
	FailedToUnmap = 0xeb0726

};


/// for custom get proc address
typedef struct _PEB_LDR_DATA64 {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;



typedef struct _LDR_DATA_TABLE_ENTRY64 {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;	
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;		
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;



typedef struct _PEB64
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PSLIST_HEADER AtlThunkSListPtr;
    PVOID IFEOKey;

    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1; // REDSTONE5
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];

    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData; // HotpatchInformation
    PVOID* ReadOnlyStaticServerData;

    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps; // PHEAP

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    KAFFINITY ActiveProcessAffinityMask;
    ULONG GdiHandleBuffer[60];
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

    SIZE_T MinimumStackCommit;

    PVOID SparePointers[2]; // 19H1 (previously FlsCallback to FlsHighIndex)
    PVOID PatchLoaderData;
    PVOID ChpeV2ProcessInfo; // _CHPEV2_PROCESS_INFO

    ULONG AppModelFeatureState;
    ULONG SpareUlongs[2];

    USHORT ActiveCodePage;
    USHORT OemCodePage;
    USHORT UseCaseMapping;
    USHORT UnusedNlsField;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;

    union
    {
        PVOID pContextData; // WIN7
        PVOID pUnused; // WIN10
        PVOID EcCodeBitMap; // WIN11
    };

    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    struct _LEAP_SECOND_DATA* LeapSecondData; // REDSTONE5
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
    ULONGLONG ExtendedFeatureDisableMask; // since WIN11
} PEB64, * PPEB64;