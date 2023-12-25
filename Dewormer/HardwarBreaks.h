#pragma once
#include "Globals.h"


BOOL Hardware_Breakpoint_Main(IN HANDLE hThread, IN WCHAR* exeName);


enum _DRX
{
	Dr0 = 0,
	Dr1 = 1,
	Dr2 = 2,
	Dr3 = 3,
};

												



