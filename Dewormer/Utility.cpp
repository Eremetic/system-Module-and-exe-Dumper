#include "Utility.h"
#include "MainFunctions.h"
#include <thread>



bool Is_Driver_Loaded()
{
	LPVOID drivers[1024] = { 0 };
	DWORD		    cbNeeded = 0;
	int      cDrivers = 0, i = 0;


	fnK32EnumDeviceDrivers pfnK32EnumDeviceDrivers = (fnK32EnumDeviceDrivers)GetProcAddress(GetModuleHandle(L"kernel32"), "K32EnumDeviceDrivers");
	fnK32GetDeviceDriverBaseNameW pfnK32GetDeviceDriverBaseNameW = (fnK32GetDeviceDriverBaseNameW)GetProcAddress(GetModuleHandle(L"kernel32"), "K32GetDeviceDriverBaseNameW");

	
	if (pfnK32EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
	{
		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (; i < cDrivers; i++)
		{
			WCHAR szDriver[MAX_PATH] = { 0 };


			if (pfnK32GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver)))
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
	int i = lstrlenW(input);
	
	WCHAR ex[MAX_PATH] = { 0 };
	for (int j = i - 3; j < i;)
	{
		for (int n = 0; n < 3; n++)
		{
			ex[n] = tolower(input[j]);
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
	ULONG					  result = 0;


	fnCreateToolhelp32Snapshot pfnCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddress(GetModuleHandle(L"kernel32"), "CreateToolhelp32Snapshot");

	hSnap = pfnCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("\033[0;31m[!]\033[0mCreatSnapShot Failed With ERROR : %lu\n", GetLastError());
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);
	
	fnProcess32FirstW pfnProcess32FirstW = (fnProcess32FirstW)GetProcAddress(GetModuleHandle(L"kernel32"), "Process32FirstW");
	
	if (!pfnProcess32FirstW(hSnap, &pe32))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Query Initial Proccess\n");
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}

	fnProcess32NextW pfnProcess32NextW = (fnProcess32NextW)GetProcAddress(GetModuleHandle(L"kernel32"), "Process32NextW");

	do
	{

		if (pPid == pe32.th32ProcessID)
		{
			WCHAR* result = pe32.szExeFile;
			return result;
		}

	} while (pfnProcess32NextW(hSnap, &pe32));


	return (WCHAR*)"Invalid";
}




bool Module_Cmp(LPWSTR input)
{
	LPVOID drivers[1024] = { 0 };
	DWORD		    cbNeeded = 0;
	int      cDrivers = 0, i = 0;

	
	fnK32EnumDeviceDrivers pfnK32EnumDeviceDrivers = (fnK32EnumDeviceDrivers)GetProcAddress(GetModuleHandle(L"kernel32"), "K32EnumDeviceDrivers");
	fnK32GetDeviceDriverBaseNameW pfnK32GetDeviceDriverBaseNameW = (fnK32GetDeviceDriverBaseNameW)GetProcAddress(GetModuleHandle(L"kernel32"), "K32GetDeviceDriverBaseNameW");

	
	if (pfnK32EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
	{
		WCHAR szDriver[MAX_PATH] = { 0 };

		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (; i < cDrivers; i++)
		{
			if (pfnK32GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver)))
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


	fnCreateToolhelp32Snapshot pfnCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddress(GetModuleHandle(L"kernel32"), "CreateToolhelp32Snapshot");

	hSnap = pfnCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("\033[0;31m[!]\033[0mCreatSnapShot Failed With ERROR : %lu\n", GetLastError());
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);

	
	fnProcess32FirstW pfnProcess32FirstW = (fnProcess32FirstW)GetProcAddress(GetModuleHandle(L"kernel32"), "Process32FirstW");
	
	if (!pfnProcess32FirstW(hSnap, &pe32))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Query Initial Proccess\n");
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}

	fnProcess32NextW pfnProcess32NextW = (fnProcess32NextW)GetProcAddress(GetModuleHandle(L"kernel32"), "Process32NextW");
	
	do
	{
		if (RSHasher(pProc, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			return result;
		}
	} while (pfnProcess32NextW(hSnap, &pe32));


	return 0;
}



static int Num_Gen()
{
	srand(time(NULL));
	int i = (rand() % (41 - 15 + 1)) + 15;

	return i;
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

BOOL RSHasher(IN PWCHAR String1 , IN PWCHAR String2)
{
	int S1_Value = 0;
	int S2_Value = 0;
	int intial_Seed = Num_Gen();

	for (int i = 0; i < wcslen(String1); i++)
	{
		S1_Value = String1[i] + RS_Sub(S1_Value, intial_Seed);
	}

	for (int i = 0; i < wcslen(String2); i++)
	{
		S2_Value = String2[i] + RS_Sub(S2_Value, intial_Seed);
	}

	if (S2_Value == S1_Value)
	{
		return TRUE;
	}
		

	return FALSE;
}




BOOL Progress_Bar(int pMax, char symbol)
{
#define green "\x1B[32m"
#define reset "\033[0m"
	
	std::string progress_bar;
	const double level = 10;
	float percentage = 0;
	
	
	if (pMax == 1) percentage = 0;
	if (pMax > 1) percentage = (pMax * 10) - 10; 
	
	progress_bar.insert(0, percentage, symbol);
	for (; percentage <= (level * pMax); percentage ++)
	{
		progress_bar.insert(0, 1, symbol);
		std::cout << "\r[" << green <<std::ceil(percentage) << '%' << reset << "] " << progress_bar;
		std::this_thread::sleep_for(std::chrono::nanoseconds(800));
		if (percentage == 100) break;
	}
	

	return true;
}