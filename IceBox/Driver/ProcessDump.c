#include "ProcessDump.h"
#include "Utility.h"


static LPVOID Process_Query(INT64 Pid, OUT PULONG szProcess)
{
#ifdef _DEBUG 
	DbgPrint("[+]Process_Query() Function Called With ProcessID : %lld\n", Pid);
#endif

	NTSTATUS			             status = 0;
	PEPROCESS				 process = NULL;
	PPEB64					   wow64 = NULL;
	PPEB_LDR_DATA			           ldr64 = NULL;
	LPVOID					baseAddr = NULL;
	ULONG					  imageSize = 0;
	PKLDR_DATA_TABLE_ENTRY                 kLdrEntry = NULL,
					       kLdrFirst = NULL;						 


	RtlSecureZeroMemory(&wow64, sizeof(PEB64));
	RtlSecureZeroMemory(&ldr64, sizeof(PEB_LDR_DATA));
	RtlSecureZeroMemory(&kLdrEntry, sizeof(KLDR_DATA_TABLE_ENTRY));
	RtlSecureZeroMemory(&kLdrFirst, sizeof(KLDR_DATA_TABLE_ENTRY));

	
	
	if(NT_SUCCESS(status = PsLookupProcessByProcessId(C_PTR(Pid), &process)))
	{

	Copy_Physical(C_PTR(wow64), C_PTR(((ULONG_PTR)process + PEB)), sizeof(PEB64));
	
	baseAddr = PsGetProcessSectionBaseAddress(process);
	
	
	#ifdef _DEBUG 
	DbgPrint("[+]Base Address : 0x%I64x\n", baseAddr);
	#endif
	if (wow64)
	{
		Copy_Physical(C_PTR(ldr64), C_PTR(wow64->Ldr), sizeof(PEB_LDR_DATA));
	
		if (ldr64->Initialized)
		{
			Copy_Physical(C_PTR(kLdrFirst), C_PTR((ldr64->InMemoryOrderModuleList.Flink - 0x10)), sizeof(KLDR_DATA_TABLE_ENTRY));
			Copy_Physical(C_PTR(kLdrEntry), C_PTR(kLdrFirst), sizeof(KLDR_DATA_TABLE_ENTRY));
	
			if (kLdrEntry)
			{
				while (1)
				{
	
					if (kLdrEntry->DllBase == baseAddr)
					{
						imageSize = kLdrEntry->SizeOfImage;
	#ifdef _DEBUG 
						DbgPrint("[+]Image Size of : %lu\n", imageSize);
	#endif
						break;
					}
	
					Copy_Physical(kLdrEntry, C_PTR(kLdrEntry->InLoadOrderLinks.Flink), sizeof(KLDR_DATA_TABLE_ENTRY));
					if (kLdrEntry == kLdrFirst) break;
				}
			}
			else
	#ifdef _DEBUG 
				DbgPrint("[!]Failed To Get LDR Data Entry\n");
	#endif
		}
		else
	#ifdef _DEBUG 
			DbgPrint("[!]Failed To Get PEB LOADER DATA\n");
	#endif
	}
	else
	#ifdef _DEBUG 
	DbgPrint("[!]Failed To Get PEB\n");
	#endif	
	ObDereferenceObject(process);
	}
	else
	#ifdef _DEBUG 
	DbgPrint("[!]Failed To Get EPROCESS With ERROR : 0x%I64x\n", status);
	#endif	
	
	
	
	
	
	if (baseAddr != NULL && imageSize != 0)
	{
	#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull\n");
	#endif
	
	*szProcess = imageSize;
	ObDereferenceObject(process);
	return baseAddr;
}

#ifdef _DEBUG 
DbgPrint("[+]Operation Unsuccessfull\n");
#endif

return NULL;
}





static ULONG Read_Write_File(IN LPVOID BaseAddr, IN WCHAR* DumpFolder, IN WCHAR* DumpName, IN ULONG szBuffer)
{
#ifdef _DEBUG 
	DbgPrint("[+]Read_Write_File() Function Called\n");
#endif


	ULONG			    status = 0;
	MM_COPY_ADDRESS 	p_Copy = { 0 };
        SIZE_T			     Bytes = 0;
	LPVOID			pBuffer = NULL;

	///securing and zero struct
	RtlSecureZeroMemory(&p_Copy, sizeof(MM_COPY_ADDRESS));

	///getting physical addres of module base
	p_Copy.PhysicalAddress = MmGetPhysicalAddress(BaseAddr);

	///allocating new buffer for dump
	pBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, szBuffer, TAG);
	if (pBuffer != NULL)
	{
		__try
		{
			///reading physical memory
			KeEnterCriticalRegion();

			MmCopyMemory(pBuffer, p_Copy, szBuffer, MM_COPY_MEMORY_PHYSICAL, &Bytes);
			status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{

#ifdef _DEBUG 
			DbgPrint("[!]Operation UnSuccessfull\n");
#endif

			status = STATUS_MM_COPY_FAILED;
			goto end;
		}
	}
	else
	{

#ifdef _DEBUG 
		DbgPrint("[!]Operation UnSuccessfull\n");
#endif

		status = STATUS_FAILED_BUFFER_ALLOC;
		goto end;
	}

	KeLeaveCriticalRegion();
	///virtual to raw header fix
	if (!NT_SUCCESS(status = Fix_Headers(pBuffer)))
	{
		return status;
	}


	IO_STATUS_BLOCK				  dirp_sb = { 0 },
		filep_sb = { 0 },
		writep_sb = { 0 };
	OBJECT_ATTRIBUTES		   dir_objatt = { 0 },
		file_objatt = { 0 };
	HANDLE					   file_Handle = NULL,
		Dir_Handle = NULL;
	UNICODE_STRING				 file_Dir = { 0 },
		dump_File = { 0 };

	///converting wchar to unicode
	RtlInitUnicodeString(&file_Dir, DumpFolder);
	RtlInitUnicodeString(&dump_File, DumpName);


	///securing memory and zeroing structs
	RtlSecureZeroMemory(&dirp_sb, sizeof(IO_STATUS_BLOCK));
	RtlSecureZeroMemory(&filep_sb, sizeof(IO_STATUS_BLOCK));
	RtlSecureZeroMemory(&writep_sb, sizeof(IO_STATUS_BLOCK));
	RtlSecureZeroMemory(&dir_objatt, sizeof(OBJECT_ATTRIBUTES));
	RtlSecureZeroMemory(&file_objatt, sizeof(OBJECT_ATTRIBUTES));


	InitializeObjectAttributes(&dir_objatt, &file_Dir, OBJ_KERNEL_HANDLE, NULL, NULL);

	if (NT_SUCCESS(status = ZwCreateFile(&Dir_Handle, DELETE,
		&dir_objatt, &dirp_sb, NULL, FILE_ATTRIBUTE_DIRECTORY, 0,
		FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0)))
	{

		InitializeObjectAttributes(&file_objatt, &dump_File, OBJ_KERNEL_HANDLE, NULL, NULL);

		if (NT_SUCCESS(status = ZwCreateFile(&file_Handle, GENERIC_ALL,
			&file_objatt, &filep_sb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
			FILE_SUPERSEDE, FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
		{
			///writing to file
			if (NT_SUCCESS(status = ZwWriteFile(
				file_Handle, NULL, NULL, NULL, &writep_sb,
				pBuffer, szBuffer, NULL, NULL)))
			{
#ifdef _DEBUG 
				DbgPrint("[+]Operation Successfull\n");
#endif
			}
			else
			{

#ifdef _DEBUG 
				DbgPrint("[!]Operation UnSuccessfull\n");
#endif

				ZwDeleteFile(&dir_objatt);
				ZwDeleteFile(&file_objatt);
				status = STATUS_FAILED_TO_WRITE;
			}
		}
		else
		{

#ifdef _DEBUG 
			DbgPrint("[!]Operation UnSuccessfull\n");
#endif

			status = STATUS_FAILED_TO_CREATE_FILE;
		}
	}
	else
	{

#ifdef _DEBUG 
		DbgPrint("[!]Operation UnSuccessfull\n");
#endif

		status = STATUS_FAILED_TO_CREATE_DIR;
	}



	ZwClose(Dir_Handle);
	ZwClose(file_Handle);
end:

	return status;
}





ULONG Dump_Process(IN INT64 pPid, IN WCHAR* DumpFolder, IN WCHAR* DumpName)
{
#ifdef _DEBUG 
	DbgPrint("[+]Dump_Process() Function Called\n");
	DbgPrint("[+]PID : %d\n", pPid);
	DbgPrint("[+]DumpFolder : %ws\n", DumpFolder);
	DbgPrint("[+]DumpName : %ws\n", DumpName);
#endif



	ULONG	   szImage = 0,
		    status = 0;
	LPVOID baseAddr = NULL;
	


	baseAddr = Process_Query(pPid, &szImage);
	if (baseAddr)
	{
		if (NT_SUCCESS(status = PE_Check(C_PTR(baseAddr))))
		{
			if (NT_SUCCESS(status = Read_Write_File(baseAddr, DumpFolder, DumpName, szImage)))
			{
#ifdef _DEBUG 
				DbgPrint("[!]Operation Successfull\n");
#endif
				return status;
			}
		}	
	}
	else
	status = STATUS_FAILED_BASE_ADDR;

#ifdef _DEBUG 
	DbgPrint("[!]Operation Unsuccessfull With Status 0x%I64x\n", status);
#endif
	
	
	return status;
}
