#include "HardwarBreaks.h"
#include "HWBPUtilities.h"


#define ERROR_BUF_SIZE	1024
 


static BOOL ReportError(IN PCWSTR szApiFuncName, IN OPTIONAL ULONGLONG uError) 
{

	CHAR cBuffer[ERROR_BUF_SIZE];
	if (_snprintf_s(cBuffer, ERROR_BUF_SIZE, _TRUNCATE, "[!] %ws Failed With Error %s\n", szApiFuncName, uError != NULL ? "0x%0.8X" : "%d") == -1)
		printf_s("[!] _snprintf_s : String Exceed The Buffer Size [ %d ] \n", ERROR_BUF_SIZE);
	else
		printf_s(cBuffer, uError != NULL ? uError : GetLastError());

	return FALSE;
}





static unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) 
{
	unsigned long long mask = (1UL << NmbrOfBitsToModify) - 1UL;
	unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);

	return NewDr7Register;
}



static BOOL SetHardwareBreakingPnt(IN HANDLE hThread, IN PVOID pAddress, IN _DRX Drx)
{

	if (!pAddress)
		return FALSE;

	CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	
	if (!GetThreadContext(hThread, &ThreadCtx))
		return ReportError(TEXT("GetThreadContext"), NULL);


	switch (Drx) 
	{
		case Dr0: 
		{
			if (!ThreadCtx.Dr0)
				ThreadCtx.Dr0 = reinterpret_cast<DWORD64>(pAddress);
			break;
		}
		case Dr1: 
		{
			if (!ThreadCtx.Dr1)
				ThreadCtx.Dr1 = reinterpret_cast<DWORD64>(pAddress);
			break;
		}
		case Dr2: 
		{
			if (!ThreadCtx.Dr2)
				ThreadCtx.Dr2 = reinterpret_cast<DWORD64>(pAddress);
			break;
		}
		case Dr3: 
		{
			if (!ThreadCtx.Dr3)
				ThreadCtx.Dr3 = reinterpret_cast<DWORD64>(pAddress);
			break;
		}
		default:
			return FALSE;
	}

	

	ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, (Drx * 2), 1, 1);


	if (!SetThreadContext(hThread, &ThreadCtx))
		return ReportError(TEXT("SetThreadContext"), NULL);

	return TRUE;
}



static BOOL RemoveHardwareBreakingPnt(IN HANDLE hThread, IN _DRX Drx)
{

	CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!GetThreadContext(hThread, &ThreadCtx))
		return ReportError(TEXT("GetThreadContext"), NULL);



	switch (Drx) 
	{
		case Dr0: 
		{
			ThreadCtx.Dr0 = 0x00;
			break;
		}
		case Dr1:
		{
			ThreadCtx.Dr1 = 0x00;
			break;
		}
		case Dr2: 
		{
			ThreadCtx.Dr2 = 0x00;
			break;
		}
		case Dr3: 
		{
			ThreadCtx.Dr3 = 0x00;
			break;
		}
		default:
			return FALSE;
	}
	

	ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, (Drx * 2), 1, 0);

	if (!SetThreadContext(hThread, &ThreadCtx))
		return ReportError(TEXT("SetThreadContext"), NULL);

	return TRUE;
}


BOOL Hardware_Breakpoint_Main(IN HANDLE hThread, IN WCHAR* exeName)
{
	DWORD		rThread = 1;
	PVOID	pAddress = NULL;
	printf_s("\033[0;32m[+]\033[0mPress 'O' If You Know The Offset You Want\033[0m\n");
	printf_s("\033[0;32m[+]\033[0mPress 'S' If You Know The Sig You Want\033[0m\n");
	
	
	int i = -1;
	do
	{
		i = getchar();
	} while (i != 83 && i != 115 && i != 79 && i != 111);

	if (i == 79 || i == 111)
	{
		pAddress =  Offset_Input(exeName);
	}
	/*else if (i == 83 || i == 115)
	{
		pAddress = Sig_Input(exeName);
	}*/
	
	printf_s("\033[0;32m[+]\033[0mSetting Hardware Breakpoint\033[0m\n");
	
	
	if (!SetHardwareBreakingPnt(hThread, pAddress, Dr3))
	{
		printf_s("\033[0;31m[!]\033[0m[0mOperaton Unsuccessfull\033[0m\n");
		return FALSE;
	}
	rThread = ResumeThread(hThread);
	if (rThread == -1)
	{
		printf_s("\033[0;31m[!]\033[0m[0mOperaton Unsuccessfull With Error : %d\033[0m\n", GetLastError());
		return FALSE;
	}
	
	printf_s("\033[0;32m[+]\033[0mOperaton Successfull\033[0m\n");

	return TRUE;
}