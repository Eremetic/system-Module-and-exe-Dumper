#pragma once
#include "Globals.h"


PVOID Function_PTR(IN const wchar_t* ModuleName, IN const char* ProcName);



/// camouflage 
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


///Main Functions

typedef HANDLE(__stdcall* fnCreateToolhelp32Snapshot)(
    IN DWORD dwFlags,
    IN DWORD th32ProcessID
    );


typedef BOOL(__stdcall* fnProcess32FirstW)(
    IN HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );

typedef BOOL(__stdcall* fnProcess32NextW)(
    IN  HANDLE hSnapshot,
    OUT LPPROCESSENTRY32W lppe
    );

typedef DWORD(__stdcall* fnK32GetDeviceDriverBaseNameW)(
    IN  LPVOID ImageBase,
    IN LPWSTR lpBaseName,
    IN  DWORD  nSize
    );

typedef BOOL(_stdcall* fnK32EnumDeviceDrivers)(
    OUT LPVOID* lpImageBase,
    IN  DWORD   cb,
    OUT LPDWORD lpcbNeeded
    );

///dewormer

typedef BOOL(__stdcall* fnSetConsoleTitleW)(
    _In_ LPCWSTR lpConsoleTitle
    );



