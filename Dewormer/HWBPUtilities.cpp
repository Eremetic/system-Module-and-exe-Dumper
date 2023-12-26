#include "HWBPUtilities.h"
#include "DriverInterface.h"


PVOID Offset_Input(IN WCHAR* exeName)
{
	
	LPWSTR reg = const_cast<LPWSTR>(L"\\\\.\\IceBox");
	DriverInterface						  driver(reg);
	PVOID								  Addr = NULL;
	DWORD64									input = 0;
	ULONG								   status = 1;
	PVOID								 baseAddr = 0;
	
	printf_s("\033[0;32m[+]\033[0mPlease Input The Offset You Want\n");
	
	std::cin >> input;
		
	
	printf_s("\033[0;32m[+]\033[0mYou Selected Offset : 0x%I64x\n", input);
	printf_s("\033[0;32m[+]\033[0mIf This Selection is Incorrect Press 'N' Else Press 'Y'\n");
	
	int i = -1;
	do
	{
		i = getchar();
	} while (i != 89 && i != 121 && i != 78 && i != 110);

	if (i == 78 || i == 110) Offset_Input(exeName);
	
	
	
	printf_s("\033[0;32m[+]\033[0mGetting Base Address Of Process\033[0m\n");

	
	baseAddr = driver.Get_Base_Addr(exeName);
	printf_s("\033[0;32m[+]\033[0mretrieved Base Address : 0x%I64x\n", baseAddr);
	
	if (baseAddr == 0)
	{
		printf_s("\033[0;31m[!]\033[0mOperaton Unsuccessfull With Error : %lu\033\n", status);
		return NULL;
	}
	
	Addr = C_PTR(((ULONG_PTR)baseAddr + input));

	printf_s("\033[0;32m[+]\033[0mBase Address + Offset : %p\n", Addr);
	
	return Addr;
}






PVOID Sig_Input(WCHAR* exeName)
{
	return NULL;
}