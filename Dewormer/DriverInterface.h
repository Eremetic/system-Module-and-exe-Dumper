#include "Globals.h"


class DriverInterface
{
public:
	HANDLE64 pDriver;

	::DriverInterface(LPWSTR RegistryPath)
	{
		pDriver = CreateFileW(RegistryPath, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	}
		
		
		ULONG Dump_Process(WCHAR* targetProcess, WCHAR* DumpFolder, WCHAR* DumpName)
		{
			if (pDriver == INVALID_HANDLE_VALUE) return FALSE;

			DUMP_PROCESS request{};

			DWORD  Bytes = 0;
			request.Response = 1;

			request.ProcName = targetProcess;
			request.DumpFolder = DumpFolder;
			request.DumpName = DumpName;

			DeviceIoControl(pDriver, IOCTL_DUMP_PROCESS, &request, sizeof(DUMP_PROCESS),
				&request, sizeof(DUMP_PROCESS), &Bytes, NULL);
		

			return request.Response;
		}
		
		
		
		ULONG Dump_Module(WCHAR* DumpFolder, WCHAR* DumpName, WCHAR* targetModule)
		{
			if (pDriver == INVALID_HANDLE_VALUE) return 0x0111999;
		
			DUMP_MODULE request{};

			DWORD  Bytes = 0;
			request.Response = 1;

			request.DumpFolder = DumpFolder;
			request.DumpName = DumpName;
			request.ModuleName = targetModule;
			
						
			DeviceIoControl(pDriver, IOCTL_DUMP_MODULE, &request, sizeof(DUMP_MODULE),
				&request, sizeof(DUMP_MODULE), &Bytes, NULL);
			

			return request.Response;
		}


		
		ULONG Hijack_Token(WCHAR* SystemProc, WCHAR* OurProcess)
		{
			if (pDriver == INVALID_HANDLE_VALUE) return 0x0111999;

			HIJACK_TOKEN request{};
			
			DWORD  Bytes = 0;
			request.Response = 1;

			request.TargetProc = SystemProc;
			request.OurProc = OurProcess;
			
			DeviceIoControl(pDriver, IOCTL_HIJACK_TOKEN, &request, sizeof(HIJACK_TOKEN),
				&request, sizeof(HIJACK_TOKEN), &Bytes, NULL);
			

			return request.Response;
		}

		PVOID Get_Base_Addr(WCHAR* targetProc)
		{
			if (pDriver == INVALID_HANDLE_VALUE) return NULL;

			BASE_ADDR request{};

			DWORD  Bytes = 0;
			request.BaseAddr = NULL;

			request.TargetProc = targetProc;

			DeviceIoControl(pDriver, IOCTL_PROC_BASE, &request, sizeof(BASE_ADDR),
				&request, sizeof(BASE_ADDR), &Bytes, NULL);
			


			return request.BaseAddr;
		}


		BOOL UnloadDriver()
		{
			if (pDriver == INVALID_HANDLE_VALUE) return FALSE;

			DeviceIoControl(pDriver, IOCTL_UNLOAD, NULL, NULL,
				NULL, NULL, NULL, NULL);
			{
				return TRUE;
			}
			return FALSE;
		}
	
};
