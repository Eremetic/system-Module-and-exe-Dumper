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
			if (pDriver == INVALID_HANDLE_VALUE) return 0x0111999;

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
	


		ULONG Advanced_Dump(WCHAR* targetProcess, WCHAR* DumpFolder, WCHAR* DumpName)
		{
			if (pDriver == INVALID_HANDLE_VALUE) return 0x0111999;

			ADV_DUMP_PROCESS request{};

			DWORD  Bytes = 0;

			request.ProcName = targetProcess;
			request.DumpFolder = DumpFolder;
			request.DumpName = DumpName;

			DeviceIoControl(pDriver, IOCTL_ADV_DUMP_PROCESS, &request, sizeof(ADV_DUMP_PROCESS),
				NULL, NULL, &Bytes, NULL);


			return 0x0;
		}

};
