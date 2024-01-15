#pragma once
#include "Globals.h"
#include <memoryapi.h>
#include "driverInterface.h"
#include <winternl.h>
#include "Utility.h"


BOOL UnHook_Dlls(IN int name);

#define _DLL_COUNT 9



typedef NTSTATUS(NTAPI* fnNtOpenSection)(
    PHANDLE					SectionHandle,
    ACCESS_MASK				DesiredAccess,
    POBJECT_ATTRIBUTES		ObjectAttributes
    );


typedef BOOL(__stdcall* fnK32EnumProcessModules)(
    IN HANDLE  hProcess,
    OUT HMODULE* lphModule,
    IN  DWORD   cb,
    OUT LPDWORD lpcbNeeded
    );


typedef LPVOID(__stdcall* fnMapViewOfFile)(
    IN HANDLE hFileMappingObject,
    IN DWORD  dwDesiredAccess,
    IN DWORD  dwFileOffsetHigh,
    IN DWORD  dwFileOffsetLow,
    IN SIZE_T dwNumberOfBytesToMap
    );

typedef DWORD(__stdcall* fnGetModuleFileNameW)(
    OPTIONAL HMODULE hModule,
    OUT LPWSTR lpFilename,
    IN DWORD nSize
    );

typedef BOOL(__stdcall* fnVirtualProtect)(
    IN  LPVOID lpAddress,
    IN  SIZE_T dwSize,
    IN  DWORD  flNewProtect,
    IN PDWORD lpflOldProtect
    );

typedef BOOL(__stdcall* fnUnmapViewOfFile)(
    IN LPCVOID lpBaseAddress
    );