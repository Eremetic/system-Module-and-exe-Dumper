#include <iostream>
#include <random>
#include <windows.h>
#include <time.h>
#include "MainMenu.h"



namespace RandNum
{
	char CHARSET[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

	static std::default_random_engine random{ static_cast<unsigned>(time(0)) };
	static std::mt19937 random_generator(random());
	
	static int Rand()
	{
		srand(time(NULL));
		int i = (rand() % (41 - 15 + 1)) + 15;

		return i;
	}

	static std::string generate(size_t length) {
	
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
	

	if (!SetConsoleTitleW(title))
	{
		printf_s("\033[0;31m[!]\033[0mFailed To Change Title With ERROR : %lu", GetLastError());
		Sleep(2000);
		exit(-1);
	}
	
	
	if (!Is_Driver_Loaded())
	{
		printf_s("\033[31;5m[!]Please Load Driver, And Restart For System Privileges\033[0m\n");
		for (int i = 5; i > 0; i--)
		{
			printf_s("\033[31;5m[!]Closing In %d\033[0m\r", i);
			Sleep(1000);
		}
		exit(-1);
	}
	else
	Hijack();	
	

	Main();
}
