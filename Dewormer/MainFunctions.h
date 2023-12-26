#pragma once
#include "Globals.h"

void Display_Processes();

void display_Modules();

void Dump_Process();

void Dump_Module();

void Create_Suspended();

void UnloadDriver();

void Hijack();



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

typedef BOOL(__stdcall* fnCreateProcessW)(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	IN BOOL bInheritHandles,
	IN DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	IN LPSTARTUPINFOW lpStartupInfo,
	OUT LPPROCESS_INFORMATION lpProcessInformation
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