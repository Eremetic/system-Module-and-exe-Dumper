#include "MainFunctions.h"
#include "DriverInterface.h"
#include "MainMenu.h"
#include "Utility.h"
#include "HardwarBreaks.h"

#include "resource.h"

void Display_Processes()
{	
	system("CLS");

	HANDLE		  hSnap = NULL,
			   hProcess = NULL;
	PROCESSENTRY32W		pe32{};
	DWORD  dwPriorityClass = 0;

	fnCreateToolhelp32Snapshot pfnCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddress(GetModuleHandle(L"kernel32"), "CreateToolhelp32Snapshot");
	
	hSnap = pfnCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("\033[0;31m[!]\033[0mCreatSnapShot Failed With ERROR : %lu\033[0m\n", GetLastError());
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\033[0m\n");
		Sleep(2000);
		Main();
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);


	fnProcess32FirstW pfnProcess32FirstW = (fnProcess32FirstW)GetProcAddress(GetModuleHandle(L"kernel32"), "Process32FirstW");


	if (!pfnProcess32FirstW(hSnap, &pe32))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Query Initial Proccess\033[0m\n");
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\033[0m\n");
		Sleep(2000);
		Main();
	}
	int count = 1;
	
	fnProcess32NextW pfnProcess32NextW = (fnProcess32NextW)GetProcAddress(GetModuleHandle(L"kernel32"), "Process32NextW");

	do
	{
		if (RSHasher(pe32.szExeFile, (PWCHAR)L"Dewormer.exe"))
		{
			printf_s("\n\033[34;3m######################################\033[0m\n");
			wprintf_s(L"\n\033[32;5m%d : Process Name : %s of Pid : %i\033[0m\n", count, pe32.szExeFile, pe32.th32ProcessID);

		}
			
		printf_s("\n\033[34;3m######################################\033[0m\n");
		wprintf_s(L"\n\033[34;3m%d : Process Name : %s of Pid : %i\033[0m\n", count, pe32.szExeFile, pe32.th32ProcessID);


	} while (pfnProcess32NextW(hSnap, &pe32) && count++);

	CloseHandle(hSnap);
	system("PAUSE");
	Main();
}








void display_Modules()
{
	system("CLS");
	
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
				if (RSHasher(szDriver, (PWCHAR)L"IceBox.sys"))
				{
					printf_s("\n\033[34;3m########################################\033[0m\n");
					wprintf_s(L"\n\033[32;5m%d : Module : %s\033[0m\n", i + 1, szDriver);
					
				}
						
					printf_s("\n\033[34;3m########################################\033[0m\n");
					wprintf_s(L"\n\033[34;3m%d : Module : %s\033[0m\n", i + 1, szDriver);
				
			}
			else
			{
				printf_s("\033[0;31m[!]\033[0mFailed To Get Module Name With ERROR : %lu\033[0m\n", GetLastError());
				printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\033[0m\n");
				Sleep(2000);
				Main();
			}
		}
	}
	else
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Enumerate Loaded Modules With ERROR : %lu\033[0m\n", GetLastError());
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\033[0m\n");
		Sleep(2000);
		Main();
	}

	system("PAUSE");
	Main();

}









void Dump_Process()
{
	system("CLS");
	
	LPWSTR reg = const_cast<LPWSTR>(L"\\\\.\\IceBox");
	DriverInterface				 driver(reg);
	std::string							pPid;
	ULONG						  result = 0;
	WCHAR*					            temp;
	WCHAR		   process[MAX_PATH] = { 0 };
	WCHAR		    curDir[MAX_PATH] = { 0 };
	WCHAR      dump_Folder[MAX_PATH] = { 0 };
	WCHAR        dump_Name[MAX_PATH] = { 0 };
	

	printf_s("\033[0;32m[+]\033[0mPlease Input The PID Of The Process you Wish to Dump\n");



	do
	{
		std::cin >> pPid;
		for (auto& i : pPid)
		{
			if (!isdigit(i))
			{
				printf_s("\033[0;31m[!]\033[0mPlease Input A Number\033[0m\r");
				pPid.clear();
				Sleep(2000);
				printf_s("                                            \r");
				break;
			}
		}

		ULONG select = atoi(pPid.c_str());
		temp = Proc_Comp(select);
		if (wcscmp(temp, (PWCHAR)L"Invalid") == 0)
		{
			printf_s("\033[0;31m\033[0;31m[!]\033[0mInvalid Input Please Try Again\033[0m\n");
			Sleep(1000);
			Dump_Process();
		}
		else break;


	} while (1);

	wmemcpy_s(process, MAX_PATH, temp, MAX_PATH);
	
	wprintf_s(L"\033[0;32m[+]\033[0mYou Selected : %s Of Pid : %i\r\n" "If This Selection is Incorrect Press 'N' Else Press 'Y'\n", process, atoi(pPid.c_str()));

	int i = -1;
	do
	{
		i = getchar();
	} while (i != 89 && i != 121 && i != 78 && i != 110);

	if (i == 78 || i == 110) Dump_Process();

	
	GetCurrentDirectory(MAX_PATH, curDir);

	swprintf_s(dump_Folder, MAX_PATH, L"\\??\\%s\\DUMPS", curDir);
	swprintf_s(dump_Name, MAX_PATH, L"%s\\dump_%s", dump_Folder, process);


	result = driver.Dump_Process(process, dump_Folder, dump_Name);
	
	
	printf_s("result : %lu\n", result);
	switch (result)
	{
	case 0x0f34:
		printf_s("\033[0;31m[!]\033[0mFailed To Get Base Address Of Module\033[0m\n");
		break;
	case 0x0f75171:
		printf_s("\033[0;31m[!]\033[0mFailed To Read Module Memory\033[0m\n");
		break;
	case 0x0ffff:
		printf_s("\033[0;31m[!]\033[0mFailed To Create Directory\033[0m\n");
		break;
	case 0x0fff1:
		printf_s("\033[0;31m[!]\033[0mFailed To Create File\033[0m\n");
		break;
	case 0x0f7171:
		printf_s("\033[0;31m[!]\033[0mFailed To Write Dump\033[0m\n");
		break;
	case 0x01710ff:
		printf_s("\033[0;31m[!]\033[0mMmCopyMemory Failed\033[0m\n");
		break;
	case 0x0f34f5:
		printf_s("\033[0;31m[!]\033[0mFailed To Allocate Buffer\033[0m\n");
		break;
	case 0x0111999:
		printf_s("\033[0;31m[!]\033[0mInvalid Driver Handle\033[0m\n");
		break;
	case 0x0f4250:
		printf_s("\033[0;31m[!]\033[0mFailed To Fix Headers\033[0m\n");
		break;
	case 0x0ff21716:
		printf_s("\033[0;31m[!]\033[0mFailed ZwQuerySystemInformation\033[0m\n");
		break;
	case 0x0f918:
		printf_s("\033[0;31m[!]\033[0mFailed To Get Unique Process ID\033[0m\n");
		break;
	case 0x0ff759:
		printf_s("\033[0;31m[!]\033[0mFailed To Get Process PEB\033[0m\n");
		break;
		break;
	case 0:
		printf_s("\033[0;32m[+]\033[0mOperaton Successfull, Dump Is in This Apps Directory\n");
		break;

	}


	system("PAUSE");
	Main();
}











void Dump_Module()
{
	system("CLS");

	LPWSTR reg = const_cast<LPWSTR>(L"\\\\.\\IceBox");

	DriverInterface			    driver(reg);
	bool					  check = false;
	WCHAR			input[MAX_PATH] = { 0 };
	WCHAR		   curDir[MAX_PATH] = { 0 };
	WCHAR     dump_Folder[MAX_PATH] = { 0 };
	WCHAR       dump_Name[MAX_PATH] = { 0 };
	ULONG						 result = 0;


	printf_s("\033[0;32m[+]\033[0mPlease Input The Module you Wish to Dump\n");
	
	do
	{
		std::wcin >> input;
		
		if (Ex_Cmp(input))
		{
			if (Module_Cmp(input))
			{
				check = true;
			}
			else
			{
				printf_s("\033[0;31m[!]\033[0mInvalid Input Please Try Again\033[0m");
				Dump_Module();
			}	
		}
		else
		{
			printf_s("\033[0;31m[!]\033[0mInvalid Input Please Try Again, Wrong File Extension\033[0m\n");
			Dump_Module();
		}
	} while (check == false);

	
	wprintf_s(L"\033[0;32m[+]\033[0mYou Selected : \"%s\" \r\n" "If This Selection is Incorrect Press 'N' Else Press 'Y'\n", input);
	
	int i = -1;
	do
	{
		i = getchar();
	} while (i != 88 && i != 121 && i != 78 && i != 110);

	if (i == 78 || i == 110) Dump_Module();

	GetCurrentDirectory(MAX_PATH, curDir);

	swprintf_s(dump_Folder, MAX_PATH, L"\\??\\%s\\DUMPS", curDir);
	swprintf_s(dump_Name, MAX_PATH, L"%s\\dump_%s", dump_Folder, input);

	///driver function
	result = driver.Dump_Module(dump_Folder, dump_Name, input);
	
	printf_s("result : %lu\n", result);
		switch (result)
		{
		case 0x0f34:
			printf_s("\033[0;31m[!]\033[0mFailed To Get Base Address Of Module\033[0m\n");
			break;
		case 0x0f75171:
			printf_s("\033[0;31m[!]\033[0mFailed To Read Module Memory\033[0m\n");
			break;
		case 0x0ffff:
			printf_s("\033[0;31m[!]\033[0mFailed To Create Directory\033[0m\n");
			break;
		case 0x0fff1:
			printf_s("\033[0;31m[!]\033[0mFailed To Create File\033[0m\n");
			break;
		case 0x0f7171:
			printf_s("\033[0;31m[!]\033[0mFailed To Write Dump\033[0m\n");
			break;
		case 0x01710ff:
			printf_s("\033[0;31m[!]\033[0mMmCopyMemory Failed\033[0m\n");
			break;
		case 0x0f34f5:
			printf_s("\033[0;31m[!]\033[0mFailed To Allocate Buffer\033[0m\n");
			break;
		case 0x0111999:
			printf_s("\033[0;31m[!]\033[0mInvalid Driver Handle\033[0m\n");
			break;
		case 0x0f4250:
			printf_s("\033[0;31m[!]\033[0mFailed To Fix Headers\033[0m\n");
			break;
		case 0x0ff21716:
			printf_s("\033[0;31m[!]\033[0mFailed ZwQuerySystemInformation\033[0m\n");
			break;
		case 0:
			printf_s("\033[0;32m[+]\033[0mOperaton Successfull, Dump Is in This Apps Directory\n");
			break;

		}	

	system("PAUSE");
	Main();
}










void Create_Suspended()
{
	system("CLS");
	
	printf_s("\033[0;32m[+]\033[0mPlease Select The Program you with to Create\n");
	Sleep(2000);
	
	WCHAR	   file_Name[MAX_PATH] = { 0 };
	WCHAR  selected_File[MAX_PATH] = { 0 };
	WCHAR		file_Dir[MAX_PATH] = { 0 };

	OPENFILENAMEW ofn{};
	RtlSecureZeroMemory(&ofn, sizeof(OPENFILENAMEW));
	ofn.lStructSize = sizeof(OPENFILENAMEW);
	ofn.hwndOwner = GetConsoleWindow(); 
	ofn.lpstrFilter = L".exe";
	ofn.lpstrFile = file_Name;
	ofn.lpstrFileTitle = selected_File;
	ofn.nMaxFileTitle = MAX_PATH;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = L"Select a Executable";
	ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;

	if (!GetOpenFileNameW(&ofn))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Create Modal With ERROR : %lu\n", GetLastError());
	}

	wprintf_s(L"\033[0;32m[+]\033[0mYou Selected : \"%s\" \r\n" "If This Selection is Incorrect Press 'N' Else Press 'Y'\n", selected_File);

	int i = -1;
	do
	{
		i = getchar();
	} while (i != 88 && i != 121 && i != 78 && i != 110);

	if (i == 78 || i == 110) Create_Suspended();


	int len1 = wcslen(file_Name);
	int len2 = wcslen(selected_File);

	for (int z = 0; z < len1 - len2; z++)
	{
		file_Dir[z] = file_Name[z];
	}

	STARTUPINFOW p_Si = { 0 };
	PROCESS_INFORMATION p_Pi = { 0 };

	RtlSecureZeroMemory(&p_Si, sizeof(LPSTARTUPINFOW));
	RtlSecureZeroMemory(&p_Pi, sizeof(LPPROCESS_INFORMATION));

	
	fnCreateProcessW pfnCreateProcessW = (fnCreateProcessW)GetProcAddress(GetModuleHandleW(L"KERNELBASE"), "CreateProcessW");
	
	if (!pfnCreateProcessW(file_Name, NULL, NULL, NULL,
		FALSE, CREATE_SUSPENDED, NULL, file_Dir, &p_Si, &p_Pi))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Create Process With ERROR : %lu\n", GetLastError());
	}

	ULONG pPid = Suspend_Comp(selected_File);
	if (pPid == 0)
	{
		printf("\033[0;31m[!]\033[0mFailed to Find Suspended Process\n");
	}

	
	wprintf_s(L"\033[0;32m[+]\033[0mCreated Process \"%s\" With Pid Of : %d\n", selected_File, pPid);

	
	
	printf_s("\033[0;32m[+]\033[0mPress 'B' To Install Hardware Breakpoint\r\n" "Else Press 'D' To Dump Process Remember Your Pid : %d\n", pPid);
	int n = -1;
	do
	{
		n = getchar();
	} while (n != 66 && n != 98 && n != 68 && n != 100);

	if (n == 66 || n == 98)
	{
		if (!Hardware_Breakpoint_Main(p_Pi.hThread, selected_File))
		{
			printf_s("\033[0;31m[!]\033[0mFailed To Install Hardware BreakPoint\033[0m\n");
		}
	}
	else if (n == 78 || n == 110)
	{
		CloseHandle(p_Pi.hProcess);
		CloseHandle(p_Pi.hThread);
		Dump_Process();
	}

	printf_s("\033[0;32m[+]\033[0mPress 'M' To Return To Main Menu Else Press 'D' To Dump Process Remember Your Pid : %d\n", pPid);

	int j = -1;
	do
	{
		j = getchar();
	} while (j != 77 && j != 109 && j != 78 && j != 110);

	
	CloseHandle(p_Pi.hProcess);
	CloseHandle(p_Pi.hThread);	
	
	if (j == 68 || j == 100)  Dump_Process();

	Main();
}


void UnloadDriver()
{
	system("CLS");
	LPWSTR reg = const_cast<LPWSTR>(L"\\\\.\\IceBox");
	DriverInterface driver(reg);
	


	if (!driver.UnloadDriver())
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Unload Driver\033[0m\n");
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\033[0m\n");
		Sleep(2000);
		Main();
	}
	
	system("PAUSE");
	Main();

}








void Hijack()
{
	system("CLS");
	printf_s("\033[0;32m[+]\033[0mHijacking System Privilege Token\n");

	LPWSTR reg = const_cast<LPWSTR>(L"\\\\.\\IceBox");
	DriverInterface driver(reg);
	ULONG result = driver.Hijack_Token((PWCHAR)L"System", (PWCHAR)L"Dewormer.exe");

	printf_s("\033[0;32m[+]\033[0m Result : %lu\n", result);
	switch (result)
	{
	case 0x007a:
		printf_s("\033[0;31m[!]\033[0mFailed To Find Token Address\033[0m\n");
		break;
	case 0x07e:
		printf_s("\033[0;31m[!]\033[0mFailed To Swap Token\033[0m\n");
		break;
	case 0x0397:
		printf_s("\033[0;31m[!]\033[0mFailed To Get Target EPROCESS Struct\033[0m\n");
		break;
	case 0x0ff21716:
		printf_s("\033[0;31m[!]\033[0mFailed ZwQuerySystemInformation\033[0m\n");
		break;
	case 0x0f918:
		printf_s("\033[0;31m[!]\033[0mFailed To Get Unique Process ID\033[0m\n");
		break;
	case 0:
		printf_s("\033[0;32m[+]\033[0mOperaton Successfull\033\n");
		break;
	}

	system("PAUSE");
}
