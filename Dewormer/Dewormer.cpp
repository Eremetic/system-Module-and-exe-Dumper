#include <iostream>
#include <random>
#include <windows.h>
#include <time.h>
#include "MainMenu.h"
#include "camouflage.h"
#include <thread>
#include "Utility.h"
#include "MainFunctions.h"
#include "FunctionPtrs.h"


namespace RandNum
{
	char CHARSET[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

	static std::default_random_engine random{ static_cast<unsigned>(time(0)) };
	static std::mt19937 random_generator(random());

	static int Rand()
	{
#pragma warning( push )
#pragma warning( disable : 4244)
		srand(time(NULL));
		int i = (rand() % (41 - 15 + 1)) + 15;
#pragma warning( pop ) 
		return i;
	}

	static std::string generate(size_t length) 
	{

		std::string str = CHARSET;

		while (length > str.length()) str += str;

		std::shuffle(str.begin(), str.end(), random_generator);

		return str.substr(0, length);
	}

}




int main()
{
	system("CLS");

	using namespace RandNum;
	std::string random = generate(Rand());
	std::wstring conv(random.begin() , random.end());
	LPCWSTR title = conv.c_str();
	int dll_Count = 1;

	
	fnSetConsoleTitleW pSetConsoleTitleW = (fnSetConsoleTitleW)Function_PTR(L"KERNEL32.DLL", "SetConsoleTitleW");

	if (!pSetConsoleTitleW(title))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Change Title With ERROR : %lu", GetLastError());
		Sleep(2000);
		exit(-1);
	}
#ifdef _DEBUG 
	Sleep(2000);
#endif
	Sleep(1000);
	
	if (Is_Driver_Loaded())
	{
		Hijack();	
	}

	
	printf_s("\033[0;32m[+]\033[0mUnooking All Dlls\n");
	do
	{
		Progress_Bar(dll_Count, '#');
		
		if (dll_Count < _DLL_COUNT + 1)
		{
			if (!UnHook_Dlls(dll_Count)) break;
		}
		

		dll_Count++;
	} while (dll_Count < _DLL_COUNT + 2);
	printf_s("\n");
	
	
	system("PAUSE");
	
	Main();
}


