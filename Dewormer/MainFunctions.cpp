#include "MainFunctions.h"
#include "DriverInterface.h"
#include "MainMenu.h"
#include "Utility.h"
#include "FunctionPtrs.h"
#include "camouflage.h"


	
void Display_Processes()
{
	system("CLS");
	

	HANDLE		  hSnap = NULL,
			   hProcess = NULL;
	PROCESSENTRY32W		pe32{};
	DWORD  dwPriorityClass = 0;

	fnCreateToolhelp32Snapshot pCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)Function_PTR(ToWstring(StringObf("KERNEL32.DLL")), "CreateToolhelp32Snapshot");
	fnProcess32FirstW pProcess32FirstW = (fnProcess32FirstW)Function_PTR(ToWstring(StringObf("KERNEL32.DLL")), "Process32FirstW");
	fnProcess32NextW pProcess32NextW = (fnProcess32NextW)Function_PTR(ToWstring(StringObf("KERNEL32.DLL")), "Process32NextW");
		
	hSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("\033[0;31m[!]\033[0mCreatSnapShot Failed With ERROR : %lu\033[0m\n", GetLastError());
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\033[0m\n");
		Sleep(2000);
		Main();
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);


	if (!pProcess32FirstW(hSnap, &pe32))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Query Initial Proccess\033[0m\n");
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\033[0m\n");
		Sleep(2000);
		Main();
	}
	int count = 1;


	do
	{
		if (RSHasher(pe32.szExeFile, ToWstring(StringObf("Dewormer.exe"))))
		{
			printf_s("\n\033[34;3m######################################\033[0m\n");
			wprintf_s(L"\n\033[32;5m%d : Process Name : %s of Pid : %i\033[0m\n", count, pe32.szExeFile, pe32.th32ProcessID);
		}
		
		printf_s("\n\033[34;3m######################################\033[0m\n");
		wprintf_s(L"\n\033[34;3m%d : Process Name : %s of Pid : %i\033[0m\n", count, pe32.szExeFile, pe32.th32ProcessID);
		
	} while (pProcess32NextW(hSnap, &pe32) && count++);

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


	fnK32GetDeviceDriverBaseNameW pK32GetDeviceDriverBaseNameW = (fnK32GetDeviceDriverBaseNameW)Function_PTR(ToWstring(StringObf("KERNEL32.DLL")), "K32GetDeviceDriverBaseNameW");
	fnK32EnumDeviceDrivers pK32EnumDeviceDrivers = (fnK32EnumDeviceDrivers)Function_PTR(ToWstring(StringObf("KERNEL32.DLL")), "K32EnumDeviceDrivers");


	if (pK32EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
	{
		WCHAR szDriver[MAX_PATH] = { 0 };

		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (; i < cDrivers; i++)
		{
			if (pK32GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver)))
			{
				if (RSHasher(szDriver, ToWstring(StringObf("IceBox.sys"))))
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


	LPWSTR reg = const_cast<LPWSTR>(ToWstring(StringObf("\\\\.\\IceBox")));
	DriverInterface		driver(reg);
	std::string		pPid;
	ULONG				 result = 0;
	WCHAR*				  process{};
	WCHAR		 Processv2[MAX_PATH] = { 0 };
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
		process = Proc_Comp(select);
		wmemcpy_s(Processv2, MAX_PATH, process, wcslen(process)); ///not sure why but process variable goes blank after wprintf_s below

		if (RSHasher(process, ToWstring(StringObf("Invalid"))))
		{
			printf_s("\033[0;31m\033[0;31m[!]\033[0mInvalid Input Please Try Again\033[0m\n");
			Sleep(1000);
			Dump_Process();
		}
		else break;


	} while (1);

	
	wprintf_s(L"\033[0;32m[+]\033[0mYou Selected : %s Of Pid : %i\r\n" "If This Selection is Incorrect Press 'N' Else Press 'Y'\n", process, atoi(pPid.c_str()));


	int i = -1;
	do
	{
		i = getchar();
	} while (i != 89 && i != 121 && i != 78 && i != 110);

	if (i == 78 || i == 110) Dump_Process();


	GetCurrentDirectory(MAX_PATH, curDir);

	swprintf_s(dump_Folder, MAX_PATH, ToWstring(StringObf("\\??\\%s\\DUMPS")), curDir);
	swprintf_s(dump_Name, MAX_PATH, ToWstring(StringObf("%s\\dump_%s")), dump_Folder, process);


	result = driver.Dump_Process(process, dump_Folder, dump_Name);

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
	case 0x01710ff:
		printf_s("\033[0;31m[!]\033[0mMmCopymemory Failed\033[0m\n");
		break;
	case 0xff91474:
		printf_s("\033[0;31m[!]\033[0mFailed To Get PML4E\033[0m\n");
		break;
	case 0xff87361:
		printf_s("\033[0;31m[!]\033[0mFailed To Get PDPTE\033[0m\n");
		break;
	case 0xff87361EE:
		printf_s("\033[0;31m[!]\033[0mFailed To Get Large PDPTE\033[0m\n");
		break;
	case 0xff772251:
		printf_s("\033[0;31m[!]\033[0mFailed To Get PDE\033[0m\n");
		break;
	case 0xff772251EE:
		printf_s("\033[0;31m[!]\033[0mFailed To Get Large PDE\033[0m\n");
		break;
	case 0xff00EA1:
		printf_s("\033[0;31m[!]\033[0mFailed To Get PTE\033[0m\n");
		break;
	case 0xee4321:
		printf_s("\033[0;31m[!]\033[0mFailed To Open Section\033[0m\n");
		break;
	case 0xef8698:
		printf_s("\033[0;31m[!]\033[0mFailed HAL Function\033[0m\n");
		break;
	case 0xea9921:
		printf_s("\033[0;31m[!]\033[0mFailed To Map Section\033[0m\n");
		break;
	case 0xeb0726:
		printf_s("\033[0;31m[!]\033[0mFailed To Unmap Section\033[0m\n");
		break;
	case 0x0:
		printf_s("\033[0;32m[+]\033[0mOperaton Successfull, Dump Is in This Apps Directory\n");
		break;

	}

	char task[MAX_PATH] = { 0 };
	wcstombs_s(NULL, task, MAX_PATH, process, wcslen(process));

	char taskKill[MAX_PATH] = { 0 };
	sprintf_s(taskKill, "\"taskkill /F /T /IM %s\"", task);

	system(taskKill);

	system("PAUSE");
	Main();
}








void Dump_Module()
{
	system("CLS");


	LPWSTR reg = const_cast<LPWSTR>(ToWstring(StringObf("\\\\.\\IceBox")));

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

	swprintf_s(dump_Folder, MAX_PATH, ToWstring(StringObf("\\??\\%s\\DUMPS")), curDir);
	swprintf_s(dump_Name, MAX_PATH, ToWstring(StringObf("%s\\dump_%s")), dump_Folder, input);

	///driver function
	result = driver.Dump_Module(dump_Folder, dump_Name, input);

	switch (result)
	{
	case 0x0f34:
		printf_s("\033[0;31m[!]\033[0mFailed To Get Base Address\033[0m\n");
		break;
	case 0x0f75171:
		printf_s("\033[0;31m[!]\033[0mFailed To Read Memory\033[0m\n");
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
	case 0x0:
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

	LPWSTR reg = const_cast<LPWSTR>(ToWstring(StringObf("\\\\.\\IceBox")));
	DriverInterface						  driver(reg);
	WCHAR				  file_Name[MAX_PATH] = { 0 };
	WCHAR			  selected_File[MAX_PATH] = { 0 };
	WCHAR					 curDir[MAX_PATH] = { 0 };
	WCHAR			    dump_Folder[MAX_PATH] = { 0 };
	WCHAR				  dump_Name[MAX_PATH] = { 0 };
	ULONG						  result = 0;

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
		printf_s("\033[0;31m[!]\033[0mReturning To Main Menu\n");
		Sleep(3000);
		Main();
	}

	wprintf_s(L"\033[0;32m[+]\033[0mYou Selected : \"%s\" \r\n" "If This Selection is Incorrect Press 'N' Else Press 'Y'\n", selected_File);

	int i = -1;
	do
	{
		i = getchar();
	} while (i != 88 && i != 121 && i != 78 && i != 110);

	if (i == 78 || i == 110) Create_Suspended();


	GetCurrentDirectory(MAX_PATH, curDir);

	swprintf_s(dump_Folder, MAX_PATH, ToWstring(StringObf("\\??\\%s\\DUMPS")), curDir);
	swprintf_s(dump_Name, MAX_PATH, ToWstring(StringObf("%s\\dump_%s")), dump_Folder, selected_File);


	driver.Advanced_Dump(selected_File, dump_Folder, dump_Name);


	system(reinterpret_cast<char*>(file_Name));

	printf_s("\033[0;32m[+]\033[0mOperaton Successfull, Dump Is in This Apps Directory\n");

	system("PAUSE");
	Main();
}








void Hijack()
{
	system("CLS");

	printf_s("\033[0;32m[+]\033[0mHijacking System Privilege Token\n");

	LPWSTR reg = const_cast<LPWSTR>(ToWstring(StringObf("\\\\.\\IceBox")));
	DriverInterface driver(reg);
	ULONG result = driver.Hijack_Token(ToWstring(StringObf("System")), ToWstring(StringObf("Dewormer.exe")));


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
	case 0x0:
		printf_s("\033[0;32m[+]\033[0mOperaton Successfull\033\n");
		break;
	}

	system("PAUSE");
}



