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


/// our driver
constexpr auto _DRIVER = L"IceBox.sys";

/// driver extenstions
constexpr auto _exe = L"sys";
constexpr auto _sys = L"dll";
constexpr auto _dll = L"exe";


/// Driver Interface stuff
#define IOCTL_UNLOAD	  	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1726, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_DUMP_MODULE 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1728, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_DUMP_PROCESS 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1730, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_HIJACK_TOKEN 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1732, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


typedef struct _DUMP_MODULE
{
	WCHAR* DumpFolder;
	WCHAR* DumpName;
	WCHAR* ModuleName;
	ULONG Response;
} DUMP_MODULE, * PDUMP_MODULE;

typedef struct _DUMP_PROCESS
{
	INT64 pPid;
	WCHAR* DumpFolder;
	WCHAR* DumpName;
	ULONG Response;
} DUMP_PROCESS, * PDUMP_PROCESS;

typedef struct _HIJACK_TOKEN
{
	INT64 PID;
	ULONG Response;
}HIJACK_TOKEN, * PHIJACK_TOKEN;


enum Dump
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
};

enum Token
{
	FailedToFindTokenAddress = 0x007a,
	FailedToSwapToken = 0x07e,
	FailedToGetTargetEprocess = 0x0397,
	success = 0x00000000,
	InvalidDriverHandle = 0x0111999,
};
	
