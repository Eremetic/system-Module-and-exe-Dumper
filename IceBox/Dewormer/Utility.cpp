#include "Utility.h"


///for admin check
#include <ntsecapi.h>



bool Is_Driver_Loaded()
{
	LPVOID drivers[1024] = { 0 };
	DWORD		    cbNeeded = 0;
	int      cDrivers = 0, i = 0;


	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
	{
		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (; i < cDrivers; i++)
		{
			WCHAR szDriver[MAX_PATH] = { 0 };


			if (GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver)))
			{
				
				if (RSHasher(szDriver, (PWCHAR)_DRIVER))
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

	if (RSHasher(ex, (PWCHAR)_sys) || RSHasher(ex, (PWCHAR)_dll) || RSHasher(ex, (PWCHAR)_exe))  return TRUE;

	
	return FALSE;
}




WCHAR* Suspend_Comp(ULONG pPid)
{
	HANDLE					hSnap = NULL,
		hProcess = NULL;
	PROCESSENTRY32W				  pe32{};
	DWORD			 dwPriorityClass = 0;
	ULONG					  result = 0;


	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("\033[0;31m[!]\033[0mCreatSnapShot Failed With ERROR : %lu\n", GetLastError());
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnap, &pe32))
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
			WCHAR* result = pe32.szExeFile;
			return result;
		}

	} while (Process32NextW(hSnap, &pe32));


	return (WCHAR*)"Invalid";
}




bool Module_Cmp(LPWSTR input)
{
	LPVOID drivers[1024] = { 0 };
	DWORD		    cbNeeded = 0;
	int      cDrivers = 0, i = 0;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
	{
		WCHAR szDriver[MAX_PATH] = { 0 };

		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (; i < cDrivers; i++)
		{
			if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver)))
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


	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("\033[0;31m[!]\033[0mCreatSnapShot Failed With ERROR : %lu\n", GetLastError());
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(2000);
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnap, &pe32))
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

	} while (Process32NextW(hSnap, &pe32));


	return 0;
}


 BOOL Admin_Check()
{
	ULONG					    status;
	LSA_HANDLE				 policy = NULL;
	LSA_OBJECT_ATTRIBUTES  ObjAttr = { 0 };

	RtlSecureZeroMemory(&ObjAttr, sizeof(LSA_OBJECT_ATTRIBUTES));

	status = LsaOpenPolicy(NULL, &ObjAttr,
		POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES,
		&policy);
	

	LsaClose(policy);
	if (status == 0x00000000)
	{
		return FALSE;
	}
	return TRUE;
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

