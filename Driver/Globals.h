#pragma once
#include <ntdef.h>
#include "ntifs.h"
#include <ntddk.h>
#include <minwindef.h>


PVOID suspend_Ptr;

///debug
#define _DEBUG 1337

///pool tag
#define TAG (ULONG)1300135

///pvoid cast
#define C_PTR( x ) ((void*) x )

///RSHasher
//size of char bit
#define CHAR_BIT 8
//SEED
#define _SEED 13

///error codes
#define STATUS_FAILED_BASE_ADDR       0x0f34
#define STATUS_FAILED_VIRTUAL_INFO   0x0f141
#define STATUS_FAILED_TO_READ_MEM  0x0f75171
#define STATUS_FAILED_TO_CREATE_DIR  0x0ffff
#define STATUS_FAILED_TO_CREATE_FILE 0x0fff1
#define STATUS_FAILED_TO_CREATE	      0x0f74
#define STATUS_FAILED_TO_WRITE	    0x0f7171
#define STATUS_FAILED_EMAGIC		0x0f3171
#define STATUS_FAILED_NT_SIG		0x0f1726
#define STATUS_MM_COPY_FAILED	   0x01710ff
#define STATUS_FAILED_BUFFER_ALLOC	0x0f34f5
#define STATUS_FAILED_FIRST_SECTION	0x0f4250
#define STATUS_NO_TOKEN_ADDRESS		  0x007a
#define STATUS_FAILED_TOKEN_SWAP	   0x07e
#define STATUS_FAILED_EPROCESS        0x0397
#define STATUS_FAILED_PROC_ID        0x0f918
#define STATUS_FAILED_ZW_QUERY	  0x0ff21716
#define STATUS_FAILED_IMAGE_SIZE    0x0ff759
#define STATUS_FAILED_GET_CONTEXT  0x0f79703
#define STATUS_FAILED_SET_CONTEXT  0x0ff7703
#define STATUS_FAILED_CR3			 0x06393
#define STATUS_FAILED_PML4E		   0xff91474
#define STATUS_FAILED_PDPTE		   0xff87361
#define STATUS_FAILED_LRGPDPTE	  0xff873611
#define STATUS_FAILED_PDE		  0xff772251
#define STATUS_FAILED_LRGPDE	  0xff772222
#define STATUS_FAILED_PTE		   0xff00EA1
#define STATUS_FAILED_OPEN_SECTION  0xee4321
#define STATUS_FAILED_HANDLE_REF    0xef8698
#define STATUS_FAILED_HAL 			0xea9921
#define STATUS_FAILED_MAP_SECTION   0xeb6270
#define STATUS_FAILED_UNMAP_SECTION 0xeb0726


///PEPROCESS Offsets
enum _OFFSETS
{
	DirectoryTableBase = 0x28,	///ULONGLONG
	UniqueProcessId = 0x440,	///void*
	Token = 0x4b8,	///EX_FAST_REF
};



/// for ZwQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation = 5,
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;



///custom definitions
#define IMAGE_DIRECTORY_ENTRY_EXPORT	  0
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DOS_SIG				 0x5A4D
#define IMAGE_NT_SIG			 0x00004550
#define IMAGE_SIZEOF_SHORT_NAME			  8



typedef union _VIRTUAL_ADDRESS
{
	PVOID pValue;
	ULONG_PTR value;
	struct
	{
		ULONG_PTR offset : 12;
		ULONG_PTR pt_index : 9;
		ULONG_PTR pd_index : 9;
		ULONG_PTR pdp_index : 9;
		ULONG_PTR pml4_index : 9;
		ULONG_PTR reserved : 16;
	}Bit;
} VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;



///Image Header Structs
typedef struct _IMAGE_DOS_HEADER {
	USHORT   e_magic;
	USHORT   e_cblp;
	USHORT   e_cp;
	USHORT   e_crlc;
	USHORT   e_cparhdr;
	USHORT   e_minalloc;
	USHORT   e_maxalloc;
	USHORT   e_ss;
	USHORT   e_sp;
	USHORT   e_csum;
	USHORT   e_ip;
	USHORT   e_cs;
	USHORT   e_lfarlc;
	USHORT   e_ovno;
	USHORT   e_res[4];
	USHORT   e_oemid;
	USHORT   e_oeminfo;
	USHORT   e_res2[10];
	LONG   e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;


typedef struct _IMAGE_SECTION_HEADER {
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;


typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Name;
	DWORD Base;
	DWORD NumberOfFunctions;
	DWORD NumberOfNames;
	DWORD AddressOfFunctions;
	DWORD AddressOfNames;
	DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;


typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;



typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	ULONGLONG            ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	ULONGLONG            SizeOfStackReserve;
	ULONGLONG            SizeOfStackCommit;
	ULONGLONG            SizeOfHeapReserve;
	ULONGLONG            SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER
{
	USHORT Machine;                                                        
	USHORT NumberOfSections;                                               
	ULONG TimeDateStamp;                                                   
	ULONG PointerToSymbolTable;                                          
	ULONG NumberOfSymbols;                                                  
	USHORT SizeOfOptionalHeader;                                          
	USHORT Characteristics;                                            
}IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;



///undocumented API's
NTKERNELAPI 
PVOID 
PsGetProcessSectionBaseAddress(__in PEPROCESS Process);



NTKERNELAPI
PPEB 
NTAPI 
PsGetProcessPeb(IN PEPROCESS Process);



NTKERNELAPI
NTSTATUS
IoCreateDriver(
	IN PUNICODE_STRING DriverName,
	OPTIONAL IN PDRIVER_INITIALIZE InitializationFunction
);


NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation, IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);


NTSYSAPI 
VOID 
RtlInitUnicodeString(
	OUT        PUNICODE_STRING  DestinationString,
	OPTIONAL __drv_aliasesMem PCWSTR SourceString
);


typedef PVOID(__stdcall* fnMmGetVirtualForPhysical)(PHYSICAL_ADDRESS Address);