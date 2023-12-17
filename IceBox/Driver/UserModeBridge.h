#pragma once
#include "Globals.h"

#define IO_UNLOAD_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1726, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_DUMP_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1728, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_DUMP_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1730, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_HIJACK_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1732, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


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