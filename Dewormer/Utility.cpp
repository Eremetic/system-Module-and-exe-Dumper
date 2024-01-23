#include "MainFunctions.h"
#include <thread>
#include "Utility.h"
#include "FunctionPtrs.h"
#include "camouflage.h"


bool Is_Driver_Loaded()
{

	LPVOID drivers[1024] = { 0 };
	DWORD		    cbNeeded = 0;
	int      cDrivers = 0, i = 0;


	fnK32GetDeviceDriverBaseNameW pK32GetDeviceDriverBaseNameW = (fnK32GetDeviceDriverBaseNameW)Function_PTR(L"KERNEL32.DLL", "K32GetDeviceDriverBaseNameW");
	fnK32EnumDeviceDrivers pK32EnumDeviceDrivers = (fnK32EnumDeviceDrivers)Function_PTR(L"KERNEL32.DLL", "K32EnumDeviceDrivers");


	if (pK32EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
	{
		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (; i < cDrivers; i++)
		{
			WCHAR szDriver[MAX_PATH] = { 0 };


			if (pK32GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver)))
			{

				if (RSHasher(szDriver, (PWCHAR)L"IceBox.sys"))
				{
					return TRUE;
				}
			}
			else
			{
				printf_s("\033[0;31m[!]\033[0mFailed To Get Module Name With ERROR : %lu\n", GetLastError());
			}
		}
	}
	else
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Enumerate Loaded Modules With ERROR : %lu\n", GetLastError());
	}

	return FALSE;
}






bool Ex_Cmp(LPWSTR input)
{
	size_t i = wcslen(input);

	WCHAR ex[MAX_PATH] = { 0 };
	for (size_t j = i - 3; j < i;)
	{
		for (size_t n = 0; n < 3; n++)
		{
			ex[n] = towlower(input[j]);
			j++;
		}
	}


	if (RSHasher(ex, (PWCHAR)L"dll") || RSHasher(ex, (PWCHAR)L"exe") || RSHasher(ex, (PWCHAR)L"sys"))  return TRUE;

	return FALSE;
}






WCHAR* Proc_Comp(ULONG pPid)
{

	HANDLE					hSnap = NULL,
						 hProcess = NULL;
	PROCESSENTRY32W				  pe32{};
	DWORD			 dwPriorityClass = 0;
	WCHAR		result[MAX_PATH] = { 0 };

	fnCreateToolhelp32Snapshot pCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)Function_PTR(L"KERNEL32.DLL", "CreateToolhelp32Snapshot");
	fnProcess32FirstW pProcess32FirstW = (fnProcess32FirstW)Function_PTR(L"KERNEL32.DLL", "Process32FirstW");
	fnProcess32NextW pProcess32NextW = (fnProcess32NextW)Function_PTR(L"KERNEL32.DLL", "Process32NextW");

	
	
	hSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("\033[0;31m[!]\033[0mCreatSnapShot Failed With ERROR : %lu\n", GetLastError());
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);



	if (!pProcess32FirstW(hSnap, &pe32))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Query Initial Proccess\n");
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}



	do
	{

		if (pPid == pe32.th32ProcessID)
		{		
			wmemcpy_s(result, MAX_PATH ,pe32.szExeFile, wcslen(pe32.szExeFile));
			return result;
		}

	} while (pProcess32NextW(hSnap, &pe32));


	return (WCHAR*)"Invalid";
}






bool Module_Cmp(LPWSTR input)
{

	LPVOID drivers[1024] = { 0 };
	DWORD		    cbNeeded = 0;
	int      cDrivers = 0, i = 0;

	
	fnK32GetDeviceDriverBaseNameW pK32GetDeviceDriverBaseNameW = (fnK32GetDeviceDriverBaseNameW)Function_PTR(L"KERNEL32.DLL", "K32GetDeviceDriverBaseNameW");
	fnK32EnumDeviceDrivers pK32EnumDeviceDrivers = (fnK32EnumDeviceDrivers)Function_PTR(L"KERNEL32.DLL", "K32EnumDeviceDrivers");



	if (pK32EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
	{
		WCHAR szDriver[MAX_PATH] = { 0 };

		cDrivers = cbNeeded / sizeof(drivers[0]);


		for (; i < cDrivers; i++)
		{
			if (pK32GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver)))
			{
				if (RSHasher(input, szDriver)) return true;
			}
			else
			{
				printf_s("\033[0;31m[!]\033[0mFailed To Get Module Name With ERROR : %lu\n", GetLastError());
			}
		}
	}
	else
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Enumerate Loaded Modules With ERROR : %lu\n", GetLastError());
	}

	return FALSE;
}






ULONG Suspend_Comp(WCHAR* pProc)
{

	HANDLE					hSnap = NULL,
						 hProcess = NULL;
	PROCESSENTRY32W				  pe32{};
	DWORD			 dwPriorityClass = 0;
	ULONG					  result = 0;

	fnCreateToolhelp32Snapshot pCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)Function_PTR(L"KERNEL32.DLL", "CreateToolhelp32Snapshot");
	fnProcess32FirstW pProcess32FirstW = (fnProcess32FirstW)Function_PTR(L"KERNEL32.DLL", "Process32FirstW");
	fnProcess32NextW pProcess32NextW = (fnProcess32NextW)Function_PTR(L"KERNEL32.DLL", "Process32NextW");

	hSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("\033[0;31m[!]\033[0mCreatSnapShot Failed With ERROR : %lu\n", GetLastError());
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);


	if (!pProcess32FirstW(hSnap, &pe32))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Query Initial Proccess\n");
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}


	do
	{
		if (RSHasher(pProc, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			return result;
		}
	} while (pProcess32NextW(hSnap, &pe32));


	return 0;
}




static UINT32 RS_Sub(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

BOOL RSHasher(IN WCHAR* String1, IN WCHAR* String2)
{
	int S1_Value = 0;
	int S2_Value = 0;

	for (int i = 0; i < wcslen(String1); i++)
	{
		S1_Value = String1[i] + RS_Sub(S1_Value, ObfXorKey);
	}

	for (int i = 0; i < wcslen(String2); i++)
	{
		S2_Value = String2[i] + RS_Sub(S2_Value, ObfXorKey);
	}

	if (S2_Value == S1_Value)
	{
		return TRUE;
	}


	return FALSE;
}




BOOL Progress_Bar(int pMax, char symbol)
{
#pragma warning( push )
#pragma warning( disable : 4244)
#define green "\x1B[32m"
#define reset "\033[0m"

	std::string progress_bar;
	const double level = 10;
	float percentage = 0;


	if (pMax == 1) percentage = 0;
	if (pMax > 1) percentage = (pMax * 10.0) - 10.0;

	progress_bar.insert(0, percentage, symbol);
	for (; percentage <= (level * pMax); percentage++)
	{
		progress_bar.insert(0, 1.0, symbol);
		std::cout << "\r[" << green << std::ceil(percentage) << '%' << reset << "] " << progress_bar;
		std::this_thread::sleep_for(std::chrono::nanoseconds(800));
		if (percentage == 100.0) break;
	}
#pragma warning( pop ) 

	return true;
}

