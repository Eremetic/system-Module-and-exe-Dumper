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


///debug
#define _DEBUG 1337

///pvoid cast
#define C_PTR( x ) ((void*) x )


/// Driver Interface stuff
#define IOCTL_UNLOAD		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1726, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_DUMP_MODULE	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1728, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_DUMP_PROCESS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1730, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_HIJACK_TOKEN	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1732, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_PROC_BASE		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1734, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


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

typedef struct _BASE_ADDR
{
	WCHAR* TargetProc;
	PVOID BaseAddr;
}BASE_ADDR, * PBASE_ADDR;




/// driver error codes
enum ErrorCodes
{
	Success = 0x00000000,
	FailedBaseAddress = 0x0f34,
	FailedToAllocateBuffer = 0x0f34f5,
	MmCopyMemoryFailed = 0x01710ff,
	FailedToReadMemory = 0x0f75171,
	FailedEmagicCheck = 0x0f3171,
	FailedNtSigCheck = 0x0f1726,
	FailedToCreateDirectory = 0x0ffff,
	FailedToCreateFile = 0x0fff1,
	FailedToWriteDump = 0x0f7171,
	InValidDriverHandle = 0x0111999,
	FailedFirstSection = 0x0f4250,
	FailedUlonglong2Ulong = 0x0f101017,
	///tokenHijack
	FailedToFindTokenAddress = 0x007a,
	FailedToSwapToken = 0x07e,
	FailedToGetTargetEprocess = 0x0397,
	success = 0x00000000,
	///ZwQuery
	FailedToGetProcID = 0x0f918,
	FailedZwQuery = 0x0ff21716,
	///processDump
	FailedToGetPEB = 0x0ff759,
	FailedToGetPEBLDR = 0x0ff9713,
	FailedToGetLDRdataEntry = 0x0ff773,
};



