#pragma once
#include "Utility.h"
#include "MainFunctions.h"





class Main
{
public:

	::Main()
	{
		system("CLS");
		system("Color 05");
		
		
		

		std::cout << R"(###                #####                                     
 #   ####  ###### #     #  ####    ##   #      ###### #####  
 #  #    # #      #       #    #  #  #  #      #      #    # 
 #  #      #####  #       #    # #    # #      #####  #    # 
 #  #      #      #       #    # ###### #      #      #    # 
 #  #    # #      #     # #    # #    # #      #      #    # 
###  ####  ######  #####   ####  #    # ###### ###### #####  )" << "\n";



		printf_s("\n");
		printf_s("\n");
		printf_s("\033[34;2mRelease Date - TBA\033[0m\r\n" "\033[34;2mCurrent Version 3.0.0\033[0m\n");
		printf_s("\n");
		wprintf_s(L"\033[32;5m%s Is Loaded\033[0m\n", _DRIVER);
	

		printf_s("\n");
		printf_s("\n");
		printf_s("\n");

		printf_s("\033[0;34m1)\033[0m\033[0;33m View Processes\033[0m\n");
		printf_s("\033[0;34m2)\033[0m\033[0;33m View Modules\033[0m\n");
		printf_s("\033[0;34m3)\033[0m\033[0;33m Dump Process\033[0m\n");
		printf_s("\033[0;34m4)\033[0m\033[0;33m Dump Module\033[0m\n");
		printf_s("\033[0;34m5)\033[0m\033[0;33m Create Suspended Process\033[0m\n");
		printf_s("\033[0;34m6)\033[0m\033[0;33m Unload Driver\033[0m\n");
		printf_s("\033[0;34m7)\033[0m\033[0;33m Exit\033[0m\n");

		printf_s("\n");
		printf_s("\n");
		printf_s("\n");

		
		std::string s;
		do
		{
			std::cin >> s;
			for (auto& i : s)
			{
				if (!isdigit(i))
				{
					printf_s("\033[0;31m[!]\033[0mPlease Input A Number\033[0m\r");
					s.clear();
					Sleep(2000);
					printf_s("                                            \n");
					break;
				}
				else if (atoi(s.c_str()) > 7 || atoi(s.c_str()) < 1)
				{
					printf_s("\033[0;31m[!]\033[0mInvalid Selection\033[0m\r");
					s.clear();
					Sleep(2000);
					printf_s("                           \n");
					break;

				}
				else if (atoi(s.c_str()) > 0 || atoi(s.c_str()) > 9) break;
				
			}
			

		} while (s.empty());


		switch (atoi(s.c_str()))
		{
		case 1:
			Display_Processes();
			break;
		case 2:
			display_Modules();
			break;
		case 3:
			Dump_Process();
			break;
		case 4:
			Dump_Module();
			break;
		case 5:
			Create_Suspended();
			break;
		case 6:
			UnloadDriver();
			break;
		case 7:
			exit(0);
			break;
		}
	}
};



